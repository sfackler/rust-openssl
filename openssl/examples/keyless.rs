#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate log_derive;
extern crate pretty_env_logger;
#[macro_use]
extern crate lazy_static;
extern crate foreign_types;
extern crate libc;
#[macro_use]
extern crate openssl;
extern crate openssl_sys as ffi;
#[macro_use]
extern crate openssl_errors as err;

use std::cell::RefCell;
use std::ffi::CStr;
use std::mem;
use std::net::IpAddr;
use std::ptr;
use std::slice;
use std::sync::{Arc, Condvar, Mutex, Once, ONCE_INIT};

use foreign_types::ForeignTypeRef;
use libc::*;

use ffi::*;
use openssl::{
    engine::{self, Engine, EngineRef},
    error::ErrorStack,
    ex_data::Index,
    nid::Nid,
    pkey::Private,
    rsa::{Padding, Rsa, RsaMethod, RsaRef},
};

openssl_errors! {
    pub library Keyless("Keyless engine") {
        functions {
            KEYLESS_INIT("keyless_init");
            KEYLESS_CTRL("keyless_ctrl");
            KEYLESS_FINISH("keyless_finish");
            KEYLESS_DESTROY("keyless_destroy");
            KEYLESS_RSA_PRIV_DEC("keyless_rsa_priv_dec");
            KEYLESS_RSA_SIGN("keyless_rsa_sign");
        }

        reasons {
            ENGINE_NOT_INITIALIZED("engine not initialized");
            CANT_FIND_CONTEXT("cant find context");
            CANT_SET_USER_DATA("cant set user data");
            UNKNOWN_COMMAND("unknown command");
            UTF8_ERROR("invalid UTF-8 string");
            LOCK_POISON("lock are poisoned");
            UNSUPPORTED_ALGORITHM_NID("unsupported algorithm nid");
            UNSUPPORTED_PADDING("unsupported padding");
            CONNECT_FAILED("connect to server failed");
            SEND_FAILED("send request failed");
            RECV_FAILED("receive response failed");
        }
    }
}

const TRUE: c_int = 1;
const FALSE: c_int = 0;

const ENGINE_KEYLESS_ID: &str = "keyless";
const ENGINE_KEYLESS_NAME: &str = "Keyless engine";

IMPLEMENT_DYNAMIC_CHECK_FN!();
IMPLEMENT_DYNAMIC_BIND_FN!(bind_helper);

unsafe fn bind_helper(e: *mut ENGINE, id: *const c_char) -> c_int {
    if id.is_null() || CStr::from_ptr(id).to_str() != Ok(ENGINE_KEYLESS_ID) {
        FALSE
    } else {
        let e = EngineRef::from_ptr(e);

        bind_keyless(e).map(|_| TRUE).unwrap_or(FALSE)
    }
}

#[no_mangle]
pub extern "C" fn engine_keyless() -> *mut ENGINE {
    let engine = Engine::new();

    if bind_keyless(&engine).is_ok() {
        engine.into_ptr()
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn ENGINE_load_keyless() {
    let e = Engine::new();

    if bind_keyless(&e).is_ok() {
        engine::add(&e).unwrap();

        unsafe {
            ERR_clear_error();
        }
    }
}

fn bind_keyless(e: &EngineRef) -> Result<(), ErrorStack> {
    let _ = pretty_env_logger::try_init();

    e.set_id(ENGINE_KEYLESS_ID)?;
    e.set_name(ENGINE_KEYLESS_NAME)?;
    e.set_flags(engine::Flags::NO_REGISTER_ALL)?;
    e.set_init_function(Some(keyless_init))?;
    e.set_finish_function(Some(keyless_finish))?;
    e.set_destroy_function(Some(keyless_destroy))?;
    e.set_rsa(Some(&**KEYLESS_RSA_METHOD))?;
    e.set_cmd_defns(KEYLESS_CMD_DEFNS.as_slice())?;
    e.set_ctrl_function(Some(keyless_ctrl))?;
    e.set_ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX, Some(Client::default()))?;

    Ok(())
}

const DEFAULT_MAX_RETRY_TIMES: usize = 3;

ENGINE_CMD_DEFINES! {
    static KEYLESS_CMD_DEFNS = {
        {
            KEYLESS_CMD_SERVER,
            "keyless_server",
            "the HOST[:PORT] address of keyless server",
            ENGINE_CMD_FLAG_STRING
        },
        {
            KEYLESS_CMD_MAX_RETRY_TIMES,
            "max_retry_times",
            "the maxium retry times",
            ENGINE_CMD_FLAG_NUMERIC
        }
    }
}

lazy_static! {
    static ref KEYLESS_RSA_METHOD: RsaMethod = RsaMethod::new("Keyless RSA method");
    static ref KEYLESS_ENGINE_CONTEXT_INDEX: Index<Engine, Client> =
        Engine::new_ex_index().unwrap();
    static ref KEYLESS_RSA_CONTEXT_INDEX: Index<Rsa<Private>, RsaContext> =
        Rsa::new_ex_index().unwrap();
}

#[derive(Debug, Default)]
struct Client {
    hostname: String,
    max_retry_times: Option<usize>,
    state: Mutex<RefCell<State>>,
}

#[derive(Debug)]
enum State {
    Unknown,
    Initialized,
    Connected(client::Sender, client::Receiver),
}

impl Default for State {
    fn default() -> Self {
        State::Unknown
    }
}

impl Client {
    pub fn init(&mut self, _engine: &EngineRef) -> Result<(), err::Reason<Keyless>> {
        static INIT: Once = ONCE_INIT;

        INIT.call_once(|| {
            let ossl_rsa_meth = RsaMethod::openssl();

            KEYLESS_RSA_METHOD
                .set_pub_enc(ossl_rsa_meth.pub_enc())
                .unwrap();
            KEYLESS_RSA_METHOD
                .set_pub_dec(ossl_rsa_meth.pub_dec())
                .unwrap();
            KEYLESS_RSA_METHOD
                .set_priv_enc(ossl_rsa_meth.priv_enc())
                .unwrap();
            KEYLESS_RSA_METHOD
                .set_priv_dec(Some(keyless_rsa_priv_dec))
                .unwrap();
            KEYLESS_RSA_METHOD
                .set_mod_exp(ossl_rsa_meth.mod_exp())
                .unwrap();
            KEYLESS_RSA_METHOD
                .set_bn_mod_exp(ossl_rsa_meth.bn_mod_exp())
                .unwrap();
            KEYLESS_RSA_METHOD.set_sign(Some(keyless_rsa_sign)).unwrap();
        });

        self.state
            .get_mut()
            .map_err(|_| Keyless::LOCK_POISON)?
            .replace(State::Initialized);

        Ok(())
    }

    pub fn finish(&mut self, _engine: &EngineRef) -> Result<(), err::Reason<Keyless>> {
        Ok(())
    }

    pub fn ctrl(
        &mut self,
        _engine: &EngineRef,
        cmd: c_int,
        l: c_long,
        p: *mut c_void,
        _f: Option<unsafe extern "C" fn()>,
    ) -> Result<(), err::Reason<Keyless>> {
        match cmd {
            KEYLESS_CMD_SERVER => {
                let hostname = unsafe { CStr::from_ptr(p as *const _) };

                debug!("set keyless_server = {:?}", hostname);

                self.hostname = hostname
                    .to_str()
                    .map_err(|_| Keyless::UTF8_ERROR)?
                    .to_owned();

                self.reset(State::Initialized)
            }
            KEYLESS_CMD_MAX_RETRY_TIMES => {
                debug!("set max_retry_times = {}", l);

                self.max_retry_times = Some(l as usize);

                Ok(())
            }
            _ => Err(Keyless::UNKNOWN_COMMAND),
        }
    }

    fn reset(&self, state: State) -> Result<(), err::Reason<Keyless>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Keyless::LOCK_POISON)?
            .replace(state);

        if let State::Connected(sender, receiver) = state {
            debug!("graceful shutdown receiver and waiting the pendding requests finish");

            mem::drop(sender);

            if receiver.join().is_err() {
                warn!("fail to graceful shutdown receiver")
            }
        }

        Ok(())
    }

    pub fn send(&mut self, req: proto::Request) -> Result<proto::Response, err::Reason<Keyless>> {
        let mut remaining_retry_times = self
            .max_retry_times
            .unwrap_or(DEFAULT_MAX_RETRY_TIMES)
            .max(1);

        while remaining_retry_times > 0 {
            let sender = self.sender()?;

            let next_state = if let Some(sender) = sender {
                match self.send_request(sender, &req) {
                    Ok(res) => return Ok(res),
                    Err(_) => {
                        remaining_retry_times -= 1;

                        State::Initialized
                    }
                }
            } else {
                self.connect()?
            };

            self.state
                .get_mut()
                .map_err(|_| Keyless::LOCK_POISON)?
                .replace(next_state);
        }

        Err(Keyless::SEND_FAILED)
    }

    fn sender(&self) -> Result<Option<client::Sender>, err::Reason<Keyless>> {
        let state = self.state.lock().unwrap();
        let state = state.borrow();

        match *state {
            State::Unknown => return Err(Keyless::ENGINE_NOT_INITIALIZED),
            State::Initialized => Ok(None),
            State::Connected(ref sender, _) => Ok(Some(sender.clone())),
        }
    }

    fn send_request(
        &self,
        sender: client::Sender,
        req: &proto::Request,
    ) -> Result<proto::Response, err::Reason<Keyless>> {
        let ctxt = Arc::new((Mutex::new(None), Condvar::new()));
        let receiver_ctxt = ctxt.clone();

        let callback = Box::new(move |response| {
            let &(ref lock, ref cvar) = &*receiver_ctxt;
            let mut res = lock.lock().unwrap();
            *res = Some(response);
            cvar.notify_one();
        });

        match sender.send((req.clone(), callback)) {
            Ok(_) => {
                let &(ref lock, ref cvar) = &*ctxt;
                let mut res = lock.lock().map_err(|_| Keyless::LOCK_POISON)?;
                while res.is_none() {
                    let mut res = cvar.wait(res).map_err(|_| Keyless::LOCK_POISON)?;

                    return res.take().ok_or(Keyless::RECV_FAILED);
                }

                Err(Keyless::RECV_FAILED)
            }
            Err(err) => {
                warn!("send request failed, {}", err);

                Err(Keyless::SEND_FAILED)
            }
        }
    }

    fn connect(&self) -> Result<State, err::Reason<Keyless>> {
        let (sender, receiver) = client::connect(&self.hostname).map_err(|err| {
            warn!(
                "connect to keyless server @ {} failed, {}",
                self.hostname, err
            );

            Keyless::CONNECT_FAILED
        })?;

        Ok(State::Connected(sender, receiver))
    }
}

#[derive(Debug)]
struct RsaContext {
    domain: String,
    client: IpAddr,
}

impl RsaContext {
    pub fn priv_dec(
        &self,
        rsa: &RsaRef<Private>,
        from: &[u8],
        padding: Padding,
    ) -> Result<proto::Request, err::Reason<Keyless>> {
        match padding {
            Padding::NONE | Padding::PKCS1 | Padding::PKCS1_OAEP | Padding::PKCS1_PSS => {}
            _ => return Err(Keyless::UNSUPPORTED_PADDING),
        }

        Ok(proto::Request {
            cert_digest: rsa.n().to_vec(),
            sni: self.domain.clone(),
            client: self.client.clone(),
            op: proto::OpCode::RSADecrypt,
            payload: from.to_vec(),
        })
    }

    pub fn sign(
        &self,
        rsa: &RsaRef<Private>,
        meth: Nid,
        m: &[u8],
    ) -> Result<proto::Request, err::Reason<Keyless>> {
        use proto::OpCode::*;

        let op = match meth {
            Nid::MD5_SHA1 => RSASignMD5SHA1,
            Nid::SHA1 | Nid::SHA1WITHRSA => RSASignSHA1,
            Nid::SHA224 => RSASignSHA224,
            Nid::SHA256 => RSASignSHA256,
            Nid::SHA384 => RSASignSHA384,
            Nid::SHA512 => RSASignSHA512,
            _ => return Err(Keyless::UNSUPPORTED_ALGORITHM_NID),
        };

        Ok(proto::Request {
            cert_digest: rsa.n().to_vec(),
            sni: self.domain.clone(),
            client: self.client.clone(),
            op,
            payload: m.to_vec(),
        })
    }
}

#[logfn(ok = "DEBUG", err = "ERROR")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_init(e: *mut ENGINE) -> c_int {
    let engine = EngineRef::from_ptr(e);

    engine
        .ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX)
        .ok_or(Keyless::CANT_FIND_CONTEXT)
        .and_then(|client| client.init(engine))
        .map(|_| TRUE)
        .unwrap_or_else(|reason| {
            put_error!(Keyless::KEYLESS_INIT, reason);
            FALSE
        })
}

#[logfn(ok = "DEBUG", err = "ERROR")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_finish(e: *mut ENGINE) -> c_int {
    let engine = EngineRef::from_ptr(e);

    engine
        .ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX)
        .ok_or(Keyless::CANT_FIND_CONTEXT)
        .and_then(|client| client.finish(engine))
        .map(|_| TRUE)
        .unwrap_or_else(|reason| {
            put_error!(Keyless::KEYLESS_FINISH, reason);
            FALSE
        })
}

#[logfn(ok = "DEBUG", err = "ERROR")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_destroy(e: *mut ENGINE) -> c_int {
    let _engine = EngineRef::from_ptr(e);

    TRUE
}

#[logfn(ok = "DEBUG", err = "ERROR")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_ctrl(
    e: *mut ENGINE,
    cmd: c_int,
    l: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> c_int {
    let engine = EngineRef::from_ptr(e);

    engine
        .ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX)
        .ok_or(Keyless::CANT_FIND_CONTEXT)
        .and_then(|client| client.ctrl(engine, cmd, l, p, f))
        .map(|_| TRUE)
        .unwrap_or_else(|reason| {
            put_error!(Keyless::KEYLESS_CTRL, reason);
            FALSE
        })
}

#[logfn(ok = "TRACE", err = "WARN")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_rsa_priv_dec(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut RSA,
    padding: c_int,
) -> c_int {
    let rsa = RsaRef::from_ptr(rsa);

    rsa.ex_data(*KEYLESS_RSA_CONTEXT_INDEX)
        .ok_or(Keyless::CANT_FIND_CONTEXT)
        .and_then(|ctx| {
            let to = slice::from_raw_parts_mut(to, rsa.size() as usize);

            ctx.priv_dec(
                rsa,
                slice::from_raw_parts(from, flen as usize),
                Padding::from_raw(padding),
            )
            .and_then(|req| {
                rsa.engine()
                    .ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX)
                    .ok_or(Keyless::CANT_FIND_CONTEXT)
                    .and_then(|client| client.send(req))
            })
        })
        .map(|_| TRUE)
        .unwrap_or_else(|reason| {
            put_error!(Keyless::KEYLESS_RSA_PRIV_DEC, reason);
            FALSE
        })
}

#[logfn(ok = "TRACE", err = "WARN")]
#[logfn_inputs(Trace)]
unsafe extern "C" fn keyless_rsa_sign(
    meth: c_int,
    m: *const c_uchar,
    m_length: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *const RSA,
) -> c_int {
    let rsa = RsaRef::from_ptr(rsa as *mut _);

    rsa.ex_data(*KEYLESS_RSA_CONTEXT_INDEX)
        .ok_or(Keyless::CANT_FIND_CONTEXT)
        .and_then(|ctx| {
            let sig = slice::from_raw_parts_mut(sigret, rsa.size() as usize);
            *siglen = rsa.size();

            ctx.sign(
                rsa,
                Nid::from_raw(meth),
                slice::from_raw_parts(m, m_length as usize),
            )
            .and_then(|req| {
                rsa.engine()
                    .ex_data(*KEYLESS_ENGINE_CONTEXT_INDEX)
                    .ok_or(Keyless::CANT_FIND_CONTEXT)
                    .and_then(|client| client.send(req))
            })
        })
        .map(|_| TRUE)
        .unwrap_or_else(|reason| {
            put_error!(Keyless::KEYLESS_RSA_SIGN, reason);
            FALSE
        })
}

pub mod proto {
    use std::convert::{TryFrom, TryInto};
    use std::io::{self, prelude::*, Cursor};
    use std::mem;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Tag marks the type of an Item.
    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Tag {
        /// a SHA256 Digest of a key.
        CertificateDigest = 0x01,
        /// server hostname (SNI) for the proxyed TLS server.
        ServerName = 0x02,
        /// an IPv4/6 address of the client connecting.
        ClientIP = 0x03,
        /// the Subject Key Identifier for the given key.
        SubjectKeyIdentifier = 0x04,
        /// an IPv4/6 address of the proxyed TLS server.
        ServerIP = 0x05,
        /// the CertID of the certificate
        CertID = 0x06,
        /// an opcode describing operation to be performed OR operation status.
        Opcode = 0x11,
        /// a payload to sign or encrypt OR payload response.
        Payload = 0x12,
        /// an item with a meaningless payload added for padding.
        Padding = 0x20,
    }

    impl From<u8> for Tag {
        fn from(v: u8) -> Self {
            unsafe { mem::transmute(v) }
        }
    }

    /// OpCode describing operation to be performed OR operation status.
    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum OpCode {
        /// an RSA decrypted payload.
        RSADecrypt = 0x01,
        /// an RSA signature on an MD5SHA1 hash payload.
        RSASignMD5SHA1 = 0x02,
        /// an RSA signature on an SHA1 hash payload.
        RSASignSHA1 = 0x03,
        /// an RSA signature on an SHA224 hash payload.
        RSASignSHA224 = 0x04,
        /// an RSA signature on an SHA256 hash payload.
        RSASignSHA256 = 0x05,
        /// an RSA signature on an SHA384 hash payload.
        RSASignSHA384 = 0x06,
        /// an RSA signature on an SHA512 hash payload.
        RSASignSHA512 = 0x07,

        /// an RSASSA-PSS signature on an SHA256 hash payload.
        RSAPSSSignSHA256 = 0x35,
        /// an RSASSA-PSS signature on an SHA384 hash payload.
        RSAPSSSignSHA384 = 0x36,
        /// an RSASSA-PSS signature on an SHA512 hash payload.
        RSAPSSSignSHA512 = 0x37,

        /// an ECDSA signature on an MD5SHA1 hash payload.
        ECDSASignMD5SHA1 = 0x12,
        /// an ECDSA signature on an SHA1 hash payload.
        ECDSASignSHA1 = 0x13,
        /// an ECDSA signature on an SHA224 hash payload.
        ECDSASignSHA224 = 0x14,
        /// an ECDSA signature on an SHA256 hash payload.
        ECDSASignSHA256 = 0x15,
        /// an ECDSA signature on an SHA384 hash payload.
        ECDSASignSHA384 = 0x16,
        /// an ECDSA signature on an SHA512 hash payload.
        ECDSASignSHA512 = 0x17,

        /// an Ed25519 signature on an arbitrary-length payload.
        Ed25519Sign = 0x18,

        // OpSeal asks to encrypt a blob (like a Session Ticket)
        Seal = 0x21,
        // OpUnseal asks to decrypt a blob encrypted by OpSeal
        Unseal = 0x22,
        // OpRPC executes an arbitrary exported function on the server.
        RPC = 0x23,

        // OpPing indicates a test message which will be echoed with opcode changed to OpPong.
        Ping = 0xF1,
        // OpPong indicates a response echoed from an OpPing test message.
        Pong = 0xF2,

        // OpResponse is used to send a block of data back to the client.
        Response = 0xF0,
        // Opor indicates some or has occurred, explanation is single byte in payload.
        Error = 0xFF,
    }

    impl From<u8> for OpCode {
        fn from(v: u8) -> Self {
            unsafe { mem::transmute(v) }
        }
    }

    /// or defines a 1-byte or payload.
    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Error {
        /// no error occurred.
        None = 0x00,
        /// a cryptography failure.
        Crypto = 0x01,
        /// key can't be found using the operation packet.
        KeyNotFound = 0x02,
        /// I/O read failure.
        Read = 0x03,
        /// an unsupported or incorrect version.
        VersionMismatch = 0x04,
        /// use of unknown opcode in request.
        BadOpcode = 0x05,
        /// use of response opcode in request.
        UnexpectedOpcode = 0x06,
        /// a malformed message.
        Format = 0x07,
        /// an internal or.
        Internal = 0x08,
        /// missing certificate.
        CertNotFound = 0x09,
        /// that the sealed blob is no longer unsealable.
        Expired = 0x10,
    }

    impl From<u8> for Error {
        fn from(v: u8) -> Self {
            unsafe { mem::transmute(v) }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Request {
        pub cert_digest: Vec<u8>,
        pub sni: String,
        pub client: IpAddr,
        pub op: OpCode,
        pub payload: Vec<u8>,
    }

    unsafe impl Send for Request {}

    static ID: AtomicU32 = AtomicU32::new(0);

    impl Request {
        pub fn current_id() -> u32 {
            ID.load(Ordering::Relaxed)
        }

        pub fn write_to<W: Write>(self, writer: &mut W) -> io::Result<usize> {
            let mut data = vec![];

            tlv(Tag::CertificateDigest, self.cert_digest).write_to(&mut data)?;
            tlv(Tag::ServerName, self.sni).write_to(&mut data)?;
            tlv(Tag::ClientIP, self.client).write_to(&mut data)?;
            tlv(Tag::Opcode, self.op).write_to(&mut data)?;
            tlv(Tag::Payload, self.payload).write_to(&mut data)?;

            let id = ID.fetch_add(10, Ordering::Relaxed);

            header(id, data.len() as u16).write_to(writer)?;

            writer.write_all(&data)?;

            Ok(HEADER_SIZE + data.len())
        }
    }

    #[derive(Debug)]
    pub enum Response {
        Success(Vec<u8>),
        Error(Error),
    }

    impl Response {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<(Header, Self)> {
            let header = Header::read_from(reader)?;

            let mut buf = vec![0; header.length as usize];

            reader.read_exact(&mut buf)?;

            let mut cur = Cursor::new(buf);

            let op = TLV::<OpCode>::read_from(&mut cur)?;
            let payload = TLV::<Vec<u8>>::read_from(&mut cur)?;

            let response = match op.value {
                OpCode::Response if payload.tag == Tag::Payload => Response::Success(payload.value),
                OpCode::Error if payload.tag == Tag::Payload && !payload.value.is_empty() => {
                    Response::Error(Error::from(payload.value[0]))
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid response",
                    ))
                }
            };

            Ok((header, response))
        }
    }

    pub fn header(id: u32, length: u16) -> Header {
        Header {
            version: (1, 0),
            length,
            id,
        }
    }

    const HEADER_SIZE: usize = 8;

    pub struct Header {
        pub version: (u8, u8),
        pub length: u16,
        pub id: u32,
    }

    impl Header {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
            let mut buf = [0; HEADER_SIZE];

            reader.read_exact(&mut buf)?;

            let (version, buf) = buf.split_at(2);
            let (len, id) = buf.split_at(2);

            Ok(Header {
                version: (version[0], version[1]),
                length: u16::from_ne_bytes(len.try_into().unwrap()),
                id: u32::from_ne_bytes(id.try_into().unwrap()),
            })
        }

        pub fn write_to<W: Write>(self, writer: &mut W) -> io::Result<usize> {
            let mut buf = [0; HEADER_SIZE];

            buf[0] = self.version.0;
            buf[1] = self.version.1;
            buf[2..4].copy_from_slice(&self.length.to_ne_bytes());
            buf[4..8].copy_from_slice(&self.id.to_ne_bytes());

            writer.write_all(&buf)?;

            Ok(HEADER_SIZE)
        }
    }

    pub fn tlv<V>(tag: Tag, value: V) -> TLV<V> {
        TLV { tag, value }
    }

    const TL_SIZE: usize = mem::size_of::<Tag>() + mem::size_of::<u16>();

    pub struct TLV<V> {
        pub tag: Tag,
        pub value: V,
    }

    impl<V> TLV<V> {
        fn read_tlv<R: Read>(reader: &mut R) -> io::Result<(Tag, Vec<u8>)> {
            let mut buf = [0; 3];

            reader.read_exact(&mut buf)?;

            let (&tag, buf) = buf.split_first().unwrap();
            let len = u16::from_ne_bytes(buf.try_into().unwrap()) as usize;
            let mut buf = vec![0; len];

            reader.read_exact(&mut buf)?;

            Ok((tag.into(), buf))
        }
    }

    impl TLV<OpCode> {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
            Self::read_tlv(reader).and_then(|(tag, v)| {
                if v.len() == 1 {
                    Ok(TLV {
                        tag,
                        value: OpCode::from(v[0]),
                    })
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "invalid opcode"))
                }
            })
        }

        pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
            writer.write_all(&[self.tag as u8])?;
            writer.write_all(&1u16.to_ne_bytes())?;
            writer.write_all(&[self.value as u8])?;

            Ok(TL_SIZE + 1)
        }
    }

    impl TLV<Vec<u8>> {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
            Self::read_tlv(reader).and_then(|(tag, value)| Ok(TLV { tag, value }))
        }

        pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
            writer.write(&[self.tag as u8])?;
            writer.write_all(&(self.value.len() as u16).to_ne_bytes())?;
            writer.write_all(self.value.as_slice())?;

            Ok(TL_SIZE + self.value.len())
        }
    }

    impl TLV<String> {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
            Self::read_tlv(reader).and_then(|(tag, v)| {
                let value = String::from_utf8(v).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid UTF8 string")
                })?;

                Ok(TLV { tag, value })
            })
        }

        pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
            writer.write(&[self.tag as u8])?;
            writer.write_all(&(self.value.len() as u16).to_ne_bytes())?;
            writer.write_all(self.value.as_bytes())?;

            Ok(TL_SIZE + self.value.len())
        }
    }

    impl TLV<IpAddr> {
        pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
            Self::read_tlv(reader).and_then(|(tag, v)| {
                let value = match v.len() {
                    4 => IpAddr::V4(<[u8; 4]>::try_from(v.as_slice()).unwrap().into()),
                    6 => IpAddr::V6(<[u8; 16]>::try_from(v.as_slice()).unwrap().into()),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid IP address",
                        ))
                    }
                };

                Ok(TLV { tag, value })
            })
        }

        pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
            writer.write(&[self.tag as u8])?;

            let value_size = match self.value {
                IpAddr::V4(addr) => {
                    let bytes = addr.octets();
                    writer.write_all(&(bytes.len() as u16).to_ne_bytes())?;
                    writer.write_all(&bytes)?;
                    bytes.len()
                }
                IpAddr::V6(addr) => {
                    let bytes = addr.octets();
                    writer.write_all(&(bytes.len() as u16).to_ne_bytes())?;
                    writer.write_all(&bytes)?;
                    bytes.len()
                }
            };

            Ok(TL_SIZE + value_size)
        }
    }
}

pub mod client {
    use std::collections::HashMap;
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::thread;

    use failure::Error;
    use openssl::ssl::{SslConnector, SslMethod};

    use proto::{Request, Response};

    pub type Callback = Box<Fn(Response) + Send + Sync>;
    pub type Sender = mpsc::Sender<(Request, Callback)>;
    pub type Receiver = thread::JoinHandle<Result<(), Error>>;

    pub fn connect(hostname: &str) -> Result<(Sender, Receiver), Error> {
        debug!("connect to keyless server @ {}", hostname);

        let connector = SslConnector::builder(SslMethod::tls())?.build();
        let stream = TcpStream::connect(hostname)?;
        let mut stream = connector.connect(hostname.split(':').next().unwrap(), stream)?;
        let (sender, receiver) = mpsc::channel::<(Request, Callback)>();
        let receiver = thread::spawn(move || -> Result<(), Error> {
            debug!("receiving keyless request");

            let mut callbacks = HashMap::new();

            loop {
                let (req, callback) = receiver.recv()?;
                let id = Request::current_id();

                trace!("send request #{}, {:#?}", id, req);

                req.write_to(&mut stream)?;

                let (header, res) = Response::read_from(&mut stream)?;

                trace!("received response, {:#?}", res);

                if header.id == id {
                    callback(res);
                } else {
                    callbacks.insert(id, callback);

                    if let Some(callback) = callbacks.remove(&header.id) {
                        callback(res);
                    }
                }
            }
        });

        Ok((sender, receiver))
    }
}
