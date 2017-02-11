use hex::{FromHex, ToHex};

use asn1::Asn1Time;
use bn::{BigNum, MSB_MAYBE_ZERO};
use ec::{NAMED_CURVE, EcGroup, EcKey};
use hash::MessageDigest;
use nid::X9_62_PRIME256V1;
use pkey::PKey;
use rsa::Rsa;
use stack::Stack;
use x509::{X509, X509Generator, X509Name, X509Req};
use x509::extension::{Extension, BasicConstraints, KeyUsage, ExtendedKeyUsage,
                      SubjectKeyIdentifier, AuthorityKeyIdentifier, SubjectAlternativeName};
use ssl::{SslMethod, SslContextBuilder};
use x509::extension::AltNameOption as SAN;
use x509::extension::KeyUsageOption::{DigitalSignature, KeyEncipherment};
use x509::extension::ExtKeyUsageOption::{self, ClientAuth, ServerAuth};
use nid;

fn get_generator() -> X509Generator {
    X509Generator::new()
        .set_valid_period(365 * 2)
        .add_name("CN".to_string(), "test_me".to_string())
        .set_sign_hash(MessageDigest::sha1())
        .add_extension(Extension::KeyUsage(vec![DigitalSignature, KeyEncipherment]))
        .add_extension(Extension::ExtKeyUsage(vec![ClientAuth,
                                        ServerAuth,
                                        ExtKeyUsageOption::Other("2.999.1".to_owned())]))
        .add_extension(Extension::SubjectAltName(vec![(SAN::DNS, "example.com".to_owned())]))
        .add_extension(Extension::OtherNid(nid::BASIC_CONSTRAINTS, "critical,CA:TRUE".to_owned()))
        .add_extension(Extension::OtherStr("2.999.2".to_owned(), "ASN1:UTF8:example value".to_owned()))
}

fn pkey() -> PKey {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_cert_gen() {
    let pkey = pkey();
    let cert = get_generator().sign(&pkey).unwrap();

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters

    assert_eq!(pkey.public_key_to_pem().unwrap(),
               cert.public_key().unwrap().public_key_to_pem().unwrap());
}

/// SubjectKeyIdentifier must be added before AuthorityKeyIdentifier or OpenSSL
/// is "unable to get issuer keyid." This test ensures the order of insertion
/// for extensions is preserved when the cert is signed.
#[test]
fn test_cert_gen_extension_ordering() {
    let pkey = pkey();
    get_generator()
        .add_extension(Extension::OtherNid(nid::SUBJECT_KEY_IDENTIFIER, "hash".to_owned()))
        .add_extension(Extension::OtherNid(nid::AUTHORITY_KEY_IDENTIFIER, "keyid:always".to_owned()))
        .sign(&pkey)
        .expect("Failed to generate cert with order-dependent extensions");
}

/// Proves that a passing result from `test_cert_gen_extension_ordering` is
/// deterministic by reversing the order of extensions and asserting failure.
#[test]
fn test_cert_gen_extension_bad_ordering() {
    let pkey = pkey();
    let result = get_generator()
        .add_extension(Extension::OtherNid(nid::AUTHORITY_KEY_IDENTIFIER, "keyid:always".to_owned()))
        .add_extension(Extension::OtherNid(nid::SUBJECT_KEY_IDENTIFIER, "hash".to_owned()))
        .sign(&pkey);

    assert!(result.is_err());
}

#[test]
fn test_req_gen() {
    let pkey = pkey();

    let req = get_generator().request(&pkey).unwrap();
    let reqpem = req.to_pem().unwrap();

    let req = X509Req::from_pem(&reqpem).ok().expect("Failed to load PEM");
    let cn = (*req).subject_name().entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!(0, (*req).version());
    assert_eq!(cn.data().as_slice(), b"test_me");

    // FIXME: check data in result to be correct, needs implementation
    // of X509_REQ getters
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let fingerprint = cert.fingerprint(MessageDigest::sha1()).unwrap();

    let hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let hash_vec = Vec::from_hex(hash_str).unwrap();

    assert_eq!(fingerprint, hash_vec);
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 14 17:00:03 2016 GMT");
    assert_eq!(not_after, "Aug 12 17:00:03 2026 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com")
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject.entries_by_nid(nid::PKCS9_EMAILADDRESS).next().unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(3, subject_alt_names.len());
    assert_eq!(Some("foobar.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(),
               Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names[2].ipaddress(),
               Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(subject_alt_names_iter.next().unwrap().dnsname(),
               Some("foobar.com"));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipaddress(),
               Some(&[127, 0, 0, 1][..]));
    assert_eq!(subject_alt_names_iter.next().unwrap().ipaddress(),
               Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..]));
    assert!(subject_alt_names_iter.next().is_none());
}

#[test]
fn x509_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(nid::COMMONNAME, "foobar.com").unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();;
    serial.rand(128, MSB_MAYBE_ZERO, false).unwrap();
    builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new().digital_signature().key_encipherment().build().unwrap();
    builder.append_extension(key_usage).unwrap();
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .other("2.999.1")
        .build()
        .unwrap();
    builder.append_extension(ext_key_usage).unwrap();
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_key_identifier).unwrap();
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(authority_key_identifier).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_alternative_name).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let x509 = builder.build();

    assert!(pkey.public_eq(&x509.public_key().unwrap()));

    let cn = x509.subject_name().entries_by_nid(nid::COMMONNAME).next().unwrap();
    assert_eq!("foobar.com".as_bytes(), cn.data().as_slice());
}

#[test]
fn x509_req_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(nid::COMMONNAME, "foobar.com").unwrap();
    let name = name.build();

    let mut builder = X509Req::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut extensions = Stack::new().unwrap();
    let key_usage = KeyUsage::new().digital_signature().key_encipherment().build().unwrap();
    extensions.push(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None))
        .unwrap();
    extensions.push(subject_alternative_name).unwrap();
    builder.add_extensions(&extensions).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
}

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
        "59172d9313e84459bcff27f967e79e6e9217e584");
    assert_eq!(certs[1].fingerprint(MessageDigest::sha1()).unwrap().to_hex(),
        "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875");
}

#[test]
fn issued() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();

    ca.issued(&cert).unwrap();
    cert.issued(&cert).err().unwrap();
}

#[test]
fn ecdsa_cert() {
    let mut group = EcGroup::from_curve_name(X9_62_PRIME256V1).unwrap();
    group.set_asn1_flag(NAMED_CURVE);
    let key = EcKey::generate(&group).unwrap();
    let key = PKey::from_ec_key(key).unwrap();

    let cert = X509Generator::new()
        .set_valid_period(365)
        .add_name("CN".to_owned(), "TestServer".to_owned())
        .set_sign_hash(MessageDigest::sha256())
        .sign(&key)
        .unwrap();

    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ctx.set_certificate(&cert).unwrap();
    ctx.set_private_key(&key).unwrap();
    ctx.check_private_key().unwrap();
}

#[test]
fn signature() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let signature = cert.signature();
    assert_eq!(signature.as_slice().to_hex(),
               "4af607b889790b43470442cfa551cdb8b6d0b0340d2958f76b9e3ef6ad4992230cead6842587f0ecad5\
                78e6e11a221521e940187e3d6652de14e84e82f6671f097cc47932e022add3c0cb54a26bf27fa84c107\
                4971caa6bee2e42d34a5b066c427f2d452038082b8073993399548088429de034fdd589dcfb0dd33be7\
                ebdfdf698a28d628a89568881d658151276bde333600969502c4e62e1d3470a683364dfb241f78d310a\
                89c119297df093eb36b7fd7540224f488806780305d1e79ffc938fe2275441726522ab36d88348e6c51\
                f13dcc46b5e1cdac23c974fd5ef86aa41e91c9311655090a52333bc79687c748d833595d4c5f987508f\
                e121997410d37c");
    let algorithm = cert.signature_algorithm();
    assert_eq!(algorithm.object().nid(), nid::SHA256WITHRSAENCRYPTION);
    assert_eq!(algorithm.object().to_string(), "sha256WithRSAEncryption");
}
