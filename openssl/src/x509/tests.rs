#[cfg(ossl110)]
use crate::asn1::Asn1Object;
use crate::asn1::Asn1Time;
use crate::bn::{BigNum, MsbOption};
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::{PKey, Private};
use crate::rsa::Rsa;
use crate::stack::Stack;
use crate::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use crate::x509::store::X509StoreBuilder;
#[cfg(any(ossl102, libressl261))]
use crate::x509::verify::{X509Purpose, X509VerifyFlags};
#[cfg(ossl110)]
use crate::x509::X509Builder;
use crate::x509::{X509Name, X509Req, X509StoreContext, X509VerifyResult, X509};
use hex::{self, FromHex};

fn pkey() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();

    let hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let hash_vec = Vec::from_hex(hash_str).unwrap();

    assert_eq!(hash_vec, &*fingerprint);
}

#[test]
fn test_debug() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let debugged = format!("{:#?}", cert);
    assert!(debugged.contains(r#"serial_number: "8771F7BDEE982FA5""#));
    assert!(debugged.contains(r#"signature_algorithm: sha256WithRSAEncryption"#));
    assert!(debugged.contains(r#"countryName = "AU""#));
    assert!(debugged.contains(r#"stateOrProvinceName = "Some-State""#));
    assert!(debugged.contains(r#"not_before: Aug 14 17:00:03 2016 GMT"#));
    assert!(debugged.contains(r#"not_after: Aug 12 17:00:03 2026 GMT"#));
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 14 17:00:03 2016 GMT");
    assert_eq!(not_after, "Aug 12 17:00:03 2026 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com")
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject
        .entries_by_nid(Nid::PKCS9_EMAILADDRESS)
        .next()
        .unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(Nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nameref_iterator() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let mut all_entries = subject.entries();

    let email = all_entries.next().unwrap();
    assert_eq!(
        email.object().nid().as_raw(),
        Nid::PKCS9_EMAILADDRESS.as_raw()
    );
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let cn = all_entries.next().unwrap();
    assert_eq!(cn.object().nid().as_raw(), Nid::COMMONNAME.as_raw());
    assert_eq!(cn.data().as_slice(), b"example.com");

    let friendly = all_entries.next().unwrap();
    assert_eq!(friendly.object().nid().as_raw(), Nid::FRIENDLYNAME.as_raw());
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");

    if all_entries.next().is_some() {
        panic!();
    }
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(5, subject_alt_names.len());
    assert_eq!(Some("example.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(
        subject_alt_names[2].ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(Some("test@example.com"), subject_alt_names[3].email());
    assert_eq!(Some("http://www.example.com"), subject_alt_names[4].uri());
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(
        subject_alt_names_iter.next().unwrap().dnsname(),
        Some("example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&[127, 0, 0, 1][..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().email(),
        Some("test@example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().uri(),
        Some("http://www.example.com")
    );
    assert!(subject_alt_names_iter.next().is_none());
}

#[test]
fn test_aia_ca_issuer() {
    // With AIA
    let cert = include_bytes!("../../test/aia_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let authority_info = cert.authority_info().unwrap();
    assert_eq!(authority_info.len(), 1);
    assert_eq!(authority_info[0].method().to_string(), "CA Issuers");
    assert_eq!(
        authority_info[0].location().uri(),
        Some("http://www.example.com/cert.pem")
    );
    // Without AIA
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    assert!(cert.authority_info().is_none());
}

#[test]
fn x509_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
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
    assert!(x509.verify(&pkey).unwrap());

    let cn = x509
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com");
    assert_eq!(serial, x509.serial_number().to_bn().unwrap());
}

#[test]
fn x509_req_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509Req::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut extensions = Stack::new().unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    extensions.push(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None))
        .unwrap();
    extensions.push(subject_alternative_name).unwrap();
    builder.add_extensions(&extensions).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let req = builder.build();
    assert!(req.public_key().unwrap().public_eq(&pkey));
    assert_eq!(req.extensions().unwrap().len(), extensions.len());
    assert!(req.verify(&pkey).unwrap());
}

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(
        hex::encode(certs[0].digest(MessageDigest::sha1()).unwrap()),
        "59172d9313e84459bcff27f967e79e6e9217e584"
    );
    assert_eq!(
        hex::encode(certs[1].digest(MessageDigest::sha1()).unwrap()),
        "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875"
    );
}

#[test]
fn issued() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();

    assert_eq!(ca.issued(&cert), X509VerifyResult::OK);
    assert_ne!(cert.issued(&cert), X509VerifyResult::OK);
}

#[test]
fn signature() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let signature = cert.signature();
    assert_eq!(
        hex::encode(signature.as_slice()),
        "4af607b889790b43470442cfa551cdb8b6d0b0340d2958f76b9e3ef6ad4992230cead6842587f0ecad5\
         78e6e11a221521e940187e3d6652de14e84e82f6671f097cc47932e022add3c0cb54a26bf27fa84c107\
         4971caa6bee2e42d34a5b066c427f2d452038082b8073993399548088429de034fdd589dcfb0dd33be7\
         ebdfdf698a28d628a89568881d658151276bde333600969502c4e62e1d3470a683364dfb241f78d310a\
         89c119297df093eb36b7fd7540224f488806780305d1e79ffc938fe2275441726522ab36d88348e6c51\
         f13dcc46b5e1cdac23c974fd5ef86aa41e91c9311655090a52333bc79687c748d833595d4c5f987508f\
         e121997410d37c"
    );
    let algorithm = cert.signature_algorithm();
    assert_eq!(algorithm.object().nid(), Nid::SHA256WITHRSAENCRYPTION);
    assert_eq!(algorithm.object().to_string(), "sha256WithRSAEncryption");
}

#[test]
#[allow(clippy::redundant_clone)]
fn clone_x509() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    drop(cert.clone());
}

#[test]
fn test_verify_cert() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
fn test_verify_fails() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/alt_name_cert.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(!context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
#[cfg(any(ossl102, libressl261))]
fn test_verify_fails_with_crl_flag_set_and_no_crl() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    store_bldr.set_flags(X509VerifyFlags::CRL_CHECK).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert_eq!(
        context
            .init(&store, &cert, &chain, |c| {
                c.verify_cert()?;
                Ok(c.error())
            })
            .unwrap()
            .error_string(),
        "unable to get certificate CRL"
    )
}

#[test]
#[cfg(any(ossl102, libressl261))]
fn test_verify_cert_with_purpose() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    let purpose_idx = X509Purpose::get_by_sname("sslserver")
        .expect("Getting certificate purpose 'sslserver' failed");
    let x509_purpose =
        X509Purpose::from_idx(purpose_idx).expect("Getting certificate purpose failed");
    store_bldr
        .set_purpose(x509_purpose.purpose())
        .expect("Setting certificate purpose failed");
    store_bldr.add_cert(ca).unwrap();

    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
#[cfg(any(ossl102, libressl261))]
fn test_verify_cert_with_wrong_purpose_fails() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    let purpose_idx = X509Purpose::get_by_sname("timestampsign")
        .expect("Getting certificate purpose 'timestampsign' failed");
    let x509_purpose =
        X509Purpose::from_idx(purpose_idx).expect("Getting certificate purpose failed");
    store_bldr
        .set_purpose(x509_purpose.purpose())
        .expect("Setting certificate purpose failed");
    store_bldr.add_cert(ca).unwrap();

    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert_eq!(
        context
            .init(&store, &cert, &chain, |c| {
                c.verify_cert()?;
                Ok(c.error())
            })
            .unwrap()
            .error_string(),
        "unsupported certificate purpose"
    )
}

#[cfg(ossl110)]
#[test]
fn x509_ref_version() {
    let mut builder = X509Builder::new().unwrap();
    let expected_version = 2;
    builder
        .set_version(expected_version)
        .expect("Failed to set certificate version");
    let cert = builder.build();
    let actual_version = cert.version();
    assert_eq!(
        expected_version, actual_version,
        "Obtained certificate version is incorrect",
    );
}

#[cfg(ossl110)]
#[test]
fn x509_ref_version_no_version_set() {
    let cert = X509Builder::new().unwrap().build();
    let actual_version = cert.version();
    assert_eq!(
        0, actual_version,
        "Default certificate version is incorrect",
    );
}

#[test]
fn test_save_subject_der() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.subject_name().to_der().unwrap();
    println!("der: {:?}", der);
    assert!(!der.is_empty());
}

#[test]
fn test_load_subject_der() {
    // The subject from ../../test/cert.pem
    const SUBJECT_DER: &[u8] = &[
        48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 65, 85, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12,
        10, 83, 111, 109, 101, 45, 83, 116, 97, 116, 101, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24,
        73, 110, 116, 101, 114, 110, 101, 116, 32, 87, 105, 100, 103, 105, 116, 115, 32, 80, 116,
        121, 32, 76, 116, 100, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 102, 111, 111, 98, 97, 114,
        46, 99, 111, 109,
    ];
    X509Name::from_der(SUBJECT_DER).unwrap();
}

#[test]
fn test_convert_to_text() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    const SUBSTRINGS: &[&str] = &[
        "Certificate:\n",
        "Serial Number:",
        "Signature Algorithm:",
        "Issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd\n",
        "Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=foobar.com\n",
        "Subject Public Key Info:",
    ];

    let text = String::from_utf8(cert.to_text().unwrap()).unwrap();

    for substring in SUBSTRINGS {
        assert!(
            text.contains(substring),
            "{:?} not found inside {}",
            substring,
            text
        );
    }
}

#[cfg(ossl110)]
fn prepare_cert_builder() -> (X509Builder, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "Example Name")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap(); // 2 -> X509v3
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    (builder, pkey)
}

#[test]
#[cfg(ossl110)]
fn test_key_usage() {
    // Create an X.509 certificate with an extended key usage extension.
    let (mut builder, pkey) = prepare_cert_builder();
    builder
        .append_extension(
            KeyUsage::new()
                .digital_signature()
                .non_repudiation()
                .key_encipherment()
                .data_encipherment()
                .key_agreement()
                .key_cert_sign()
                //.crl_sign()
                .decipher_only()
                .encipher_only()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let ku_bit_string = cert.key_usage().unwrap();
    assert_eq!(ku_bit_string.len(), 2);
    let mut ku_bits: u32 = 0;
    ku_bits |= ku_bit_string.as_slice()[0] as u32;
    ku_bits |= (ku_bit_string.as_slice()[1] as u32) << 8;
    assert!(ku_bits & ffi::X509v3_KU_DIGITAL_SIGNATURE > 0);
    assert!(ku_bits & ffi::X509v3_KU_NON_REPUDIATION > 0);
    assert!(ku_bits & ffi::X509v3_KU_KEY_ENCIPHERMENT > 0);
    assert!(ku_bits & ffi::X509v3_KU_DATA_ENCIPHERMENT > 0);
    assert!(ku_bits & ffi::X509v3_KU_KEY_AGREEMENT > 0);
    assert!(ku_bits & ffi::X509v3_KU_KEY_CERT_SIGN > 0);
    assert_eq!(ku_bits & ffi::X509v3_KU_CRL_SIGN, 0);
    assert!(ku_bits & ffi::X509v3_KU_ENCIPHER_ONLY > 0);
    assert!(ku_bits & ffi::X509v3_KU_DECIPHER_ONLY > 0);
}

#[test]
#[cfg(ossl110)]
fn test_key_usage_data() {
    // Create an X.509 certificate with an extended key usage extension.
    let (mut builder, pkey) = prepare_cert_builder();
    builder
        .append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let ku_ext_pos = cert.get_extension_by_nid(&Nid::KEY_USAGE).unwrap();
    let ku_ext = cert.get_extension(ku_ext_pos).unwrap();
    assert!(!ku_ext.is_critical());
    assert_eq!(
        ku_ext.object().unwrap(),
        Asn1Object::from_nid(&Nid::KEY_USAGE).unwrap().as_ref()
    );
    assert_eq!(
        ku_ext.data().unwrap().as_slice(),
        [0x03, 0x02, 0x02, 0x04,] //   BIT STRING (6 bit) 000001
    );
}

#[test]
#[cfg(ossl110)]
fn test_extended_key_usage() {
    // Create an X.509 certificate with an extended key usage extension.
    let (mut builder, pkey) = prepare_cert_builder();
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .critical()
                .server_auth()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let asn1obj_stack = cert.extended_key_usage().unwrap();
    assert_eq!(asn1obj_stack.get(0).unwrap().nid(), Nid::SERVER_AUTH)
}

#[test]
#[cfg(ossl110)]
fn test_extended_key_usage_data() {
    // Create an X.509 certificate with an extended key usage extension.
    let (mut builder, pkey) = prepare_cert_builder();
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .critical()
                .server_auth()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let eku_ext_pos = cert.get_extension_by_nid(&Nid::EXT_KEY_USAGE).unwrap();
    let eku_ext = cert.get_extension(eku_ext_pos).unwrap();
    assert!(eku_ext.is_critical());
    assert_eq!(
        eku_ext.object().unwrap(),
        Asn1Object::from_nid(&Nid::EXT_KEY_USAGE).unwrap().as_ref()
    );
    assert_eq!(
        eku_ext.data().unwrap().as_slice(),
        [
            0x30, 0x0a, // SEQUENCE LENGTH=10
            0x06, 0x08, //   OBJECT IDENTIFIER LENGTH=8
            0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 // 1.3.6.1.5.5.7.3.1 (serverAuth)
        ]
    );
}

#[test]
#[cfg(ossl110)]
fn test_extended_key_usage_flags() {
    // Create an X.509 certificate with an extended key usage extension.
    let (mut builder, pkey) = prepare_cert_builder();
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .critical()
                .client_auth()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let eku_flags = cert.extended_key_usage_flags();
    assert!(eku_flags & ffi::XKU_SSL_SERVER == 0);
    assert!(eku_flags & ffi::XKU_SSL_CLIENT == ffi::XKU_SSL_CLIENT);
}
