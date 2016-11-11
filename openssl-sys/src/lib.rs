#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(dead_code, overflowing_literals)]
#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/v0.9.1")]

extern crate libc;

use libc::{c_void, c_int, c_char, c_ulong, c_long, c_uint, c_uchar, size_t, FILE};
use std::ptr;

#[cfg(any(ossl101, ossl102))]
mod ossl10x;
#[cfg(any(ossl101, ossl102))]
pub use ossl10x::*;

#[cfg(ossl110)]
mod ossl110;
#[cfg(ossl110)]
pub use ossl110::*;

pub enum ASN1_INTEGER {}
pub enum ASN1_STRING {}
pub enum ASN1_TIME {}
pub enum ASN1_TYPE {}
pub enum BN_CTX {}
pub enum BN_GENCB {}
pub enum CONF {}
pub enum COMP_METHOD {}
pub enum EC_KEY {}
pub enum ENGINE {}
pub enum EVP_CIPHER_CTX {}
pub enum EVP_MD {}
pub enum EVP_PKEY_CTX {}
pub enum SSL {}
pub enum SSL_CIPHER {}
pub enum SSL_METHOD {}
pub enum X509_CRL {}
pub enum X509_EXTENSION {}
pub enum X509_NAME {}
pub enum X509_NAME_ENTRY {}
pub enum X509_REQ {}
pub enum X509_STORE_CTX {}
pub enum bio_st {}
pub enum PKCS12 {}
pub enum DH_METHOD {}

pub type bio_info_cb = Option<unsafe extern "C" fn(*mut BIO,
                                                   c_int,
                                                   *const c_char,
                                                   c_int,
                                                   c_long,
                                                   c_long)>;

pub enum RSA_METHOD {}
pub enum BN_MONT_CTX {}
pub enum BN_BLINDING {}
pub enum DSA_METHOD {}
pub enum EVP_PKEY_ASN1_METHOD {}

#[repr(C)]
pub struct GENERAL_NAME {
    pub type_: c_int,
    pub d: *mut c_void,
}

#[repr(C)]
pub struct X509V3_CTX {
    flags: c_int,
    issuer_cert: *mut c_void,
    subject_cert: *mut c_void,
    subject_req: *mut c_void,
    crl: *mut c_void,
    db_meth: *mut c_void,
    db: *mut c_void,
    // I like the last comment line, it is copied from OpenSSL sources:
    // Maybe more here
}

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = libc::c_ulonglong;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = c_uint;

pub type CRYPTO_EX_new = unsafe extern fn(parent: *mut c_void, ptr: *mut c_void,
                                          ad: *const CRYPTO_EX_DATA, idx: c_int,
                                          argl: c_long, argp: *const c_void) -> c_int;
pub type CRYPTO_EX_dup = unsafe extern fn(to: *mut CRYPTO_EX_DATA,
                                          from: *mut CRYPTO_EX_DATA, from_d: *mut c_void,
                                          idx: c_int, argl: c_long, argp: *mut c_void)
                                          -> c_int;
pub type CRYPTO_EX_free = unsafe extern fn(parent: *mut c_void, ptr: *mut c_void,
                                           ad: *mut CRYPTO_EX_DATA, idx: c_int,
                                           argl: c_long, argp: *mut c_void);
pub type PasswordCallback = unsafe extern fn(buf: *mut c_char, size: c_int,
                                             rwflag: c_int, user_data: *mut c_void)
                                             -> c_int;

pub const BIO_TYPE_NONE: c_int = 0;

pub const BIO_CTRL_EOF: c_int = 2;
pub const BIO_CTRL_INFO: c_int = 3;
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;

pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub const CRYPTO_LOCK: c_int = 1;

pub const EVP_MAX_MD_SIZE: c_uint = 64;
pub const EVP_PKEY_RSA: c_int = NID_rsaEncryption;
pub const EVP_PKEY_HMAC: c_int = NID_hmac;
pub const EVP_PKEY_DSA: c_int = NID_dsa;

pub const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
pub const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
pub const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

pub const MBSTRING_ASC:  c_int = MBSTRING_FLAG | 1;
pub const MBSTRING_BMP:  c_int = MBSTRING_FLAG | 2;
pub const MBSTRING_FLAG: c_int = 0x1000;
pub const MBSTRING_UNIV: c_int = MBSTRING_FLAG | 4;
pub const MBSTRING_UTF8: c_int = MBSTRING_FLAG;

pub const NID_undef: c_int = 0;
pub const NID_itu_t: c_int = 645;
pub const NID_ccitt: c_int = 404;
pub const NID_iso: c_int = 181;
pub const NID_joint_iso_itu_t: c_int = 646;
pub const NID_joint_iso_ccitt: c_int = 393;
pub const NID_member_body: c_int = 182;
pub const NID_identified_organization: c_int = 676;
pub const NID_hmac_md5: c_int = 780;
pub const NID_hmac_sha1: c_int = 781;
pub const NID_certicom_arc: c_int = 677;
pub const NID_international_organizations: c_int = 647;
pub const NID_wap: c_int = 678;
pub const NID_wap_wsg: c_int = 679;
pub const NID_selected_attribute_types: c_int = 394;
pub const NID_clearance: c_int = 395;
pub const NID_ISO_US: c_int = 183;
pub const NID_X9_57: c_int = 184;
pub const NID_X9cm: c_int = 185;
pub const NID_dsa: c_int = 116;
pub const NID_dsaWithSHA1: c_int = 113;
pub const NID_ansi_X9_62: c_int = 405;
pub const NID_X9_62_prime_field: c_int = 406;
pub const NID_X9_62_characteristic_two_field: c_int = 407;
pub const NID_X9_62_id_characteristic_two_basis: c_int = 680;
pub const NID_X9_62_onBasis: c_int = 681;
pub const NID_X9_62_tpBasis: c_int = 682;
pub const NID_X9_62_ppBasis: c_int = 683;
pub const NID_X9_62_id_ecPublicKey: c_int = 408;
pub const NID_X9_62_c2pnb163v1: c_int = 684;
pub const NID_X9_62_c2pnb163v2: c_int = 685;
pub const NID_X9_62_c2pnb163v3: c_int = 686;
pub const NID_X9_62_c2pnb176v1: c_int = 687;
pub const NID_X9_62_c2tnb191v1: c_int = 688;
pub const NID_X9_62_c2tnb191v2: c_int = 689;
pub const NID_X9_62_c2tnb191v3: c_int = 690;
pub const NID_X9_62_c2onb191v4: c_int = 691;
pub const NID_X9_62_c2onb191v5: c_int = 692;
pub const NID_X9_62_c2pnb208w1: c_int = 693;
pub const NID_X9_62_c2tnb239v1: c_int = 694;
pub const NID_X9_62_c2tnb239v2: c_int = 695;
pub const NID_X9_62_c2tnb239v3: c_int = 696;
pub const NID_X9_62_c2onb239v4: c_int = 697;
pub const NID_X9_62_c2onb239v5: c_int = 698;
pub const NID_X9_62_c2pnb272w1: c_int = 699;
pub const NID_X9_62_c2pnb304w1: c_int = 700;
pub const NID_X9_62_c2tnb359v1: c_int = 701;
pub const NID_X9_62_c2pnb368w1: c_int = 702;
pub const NID_X9_62_c2tnb431r1: c_int = 703;
pub const NID_X9_62_prime192v1: c_int = 409;
pub const NID_X9_62_prime192v2: c_int = 410;
pub const NID_X9_62_prime192v3: c_int = 411;
pub const NID_X9_62_prime239v1: c_int = 412;
pub const NID_X9_62_prime239v2: c_int = 413;
pub const NID_X9_62_prime239v3: c_int = 414;
pub const NID_X9_62_prime256v1: c_int = 415;
pub const NID_ecdsa_with_SHA1: c_int = 416;
pub const NID_ecdsa_with_Recommended: c_int = 791;
pub const NID_ecdsa_with_Specified: c_int = 792;
pub const NID_ecdsa_with_SHA224: c_int = 793;
pub const NID_ecdsa_with_SHA256: c_int = 794;
pub const NID_ecdsa_with_SHA384: c_int = 795;
pub const NID_ecdsa_with_SHA512: c_int = 796;
pub const NID_secp112r1: c_int = 704;
pub const NID_secp112r2: c_int = 705;
pub const NID_secp128r1: c_int = 706;
pub const NID_secp128r2: c_int = 707;
pub const NID_secp160k1: c_int = 708;
pub const NID_secp160r1: c_int = 709;
pub const NID_secp160r2: c_int = 710;
pub const NID_secp192k1: c_int = 711;
pub const NID_secp224k1: c_int = 712;
pub const NID_secp224r1: c_int = 713;
pub const NID_secp256k1: c_int = 714;
pub const NID_secp384r1: c_int = 715;
pub const NID_secp521r1: c_int = 716;
pub const NID_sect113r1: c_int = 717;
pub const NID_sect113r2: c_int = 718;
pub const NID_sect131r1: c_int = 719;
pub const NID_sect131r2: c_int = 720;
pub const NID_sect163k1: c_int = 721;
pub const NID_sect163r1: c_int = 722;
pub const NID_sect163r2: c_int = 723;
pub const NID_sect193r1: c_int = 724;
pub const NID_sect193r2: c_int = 725;
pub const NID_sect233k1: c_int = 726;
pub const NID_sect233r1: c_int = 727;
pub const NID_sect239k1: c_int = 728;
pub const NID_sect283k1: c_int = 729;
pub const NID_sect283r1: c_int = 730;
pub const NID_sect409k1: c_int = 731;
pub const NID_sect409r1: c_int = 732;
pub const NID_sect571k1: c_int = 733;
pub const NID_sect571r1: c_int = 734;
pub const NID_wap_wsg_idm_ecid_wtls1: c_int = 735;
pub const NID_wap_wsg_idm_ecid_wtls3: c_int = 736;
pub const NID_wap_wsg_idm_ecid_wtls4: c_int = 737;
pub const NID_wap_wsg_idm_ecid_wtls5: c_int = 738;
pub const NID_wap_wsg_idm_ecid_wtls6: c_int = 739;
pub const NID_wap_wsg_idm_ecid_wtls7: c_int = 740;
pub const NID_wap_wsg_idm_ecid_wtls8: c_int = 741;
pub const NID_wap_wsg_idm_ecid_wtls9: c_int = 742;
pub const NID_wap_wsg_idm_ecid_wtls10: c_int = 743;
pub const NID_wap_wsg_idm_ecid_wtls11: c_int = 744;
pub const NID_wap_wsg_idm_ecid_wtls12: c_int = 745;
pub const NID_cast5_cbc: c_int = 108;
pub const NID_cast5_ecb: c_int = 109;
pub const NID_cast5_cfb64: c_int = 110;
pub const NID_cast5_ofb64: c_int = 111;
pub const NID_pbeWithMD5AndCast5_CBC: c_int = 112;
pub const NID_id_PasswordBasedMAC: c_int = 782;
pub const NID_id_DHBasedMac: c_int = 783;
pub const NID_rsadsi: c_int = 1;
pub const NID_pkcs: c_int = 2;
pub const NID_pkcs1: c_int = 186;
pub const NID_rsaEncryption: c_int = 6;
pub const NID_md2WithRSAEncryption: c_int = 7;
pub const NID_md4WithRSAEncryption: c_int = 396;
pub const NID_md5WithRSAEncryption: c_int = 8;
pub const NID_sha1WithRSAEncryption: c_int = 65;
pub const NID_rsaesOaep: c_int = 919;
pub const NID_mgf1: c_int = 911;
pub const NID_rsassaPss: c_int = 912;
pub const NID_sha256WithRSAEncryption: c_int = 668;
pub const NID_sha384WithRSAEncryption: c_int = 669;
pub const NID_sha512WithRSAEncryption: c_int = 670;
pub const NID_sha224WithRSAEncryption: c_int = 671;
pub const NID_pkcs3: c_int = 27;
pub const NID_dhKeyAgreement: c_int = 28;
pub const NID_pkcs5: c_int = 187;
pub const NID_pbeWithMD2AndDES_CBC: c_int = 9;
pub const NID_pbeWithMD5AndDES_CBC: c_int = 10;
pub const NID_pbeWithMD2AndRC2_CBC: c_int = 168;
pub const NID_pbeWithMD5AndRC2_CBC: c_int = 169;
pub const NID_pbeWithSHA1AndDES_CBC: c_int = 170;
pub const NID_pbeWithSHA1AndRC2_CBC: c_int = 68;
pub const NID_id_pbkdf2: c_int = 69;
pub const NID_pbes2: c_int = 161;
pub const NID_pbmac1: c_int = 162;
pub const NID_pkcs7: c_int = 20;
pub const NID_pkcs7_data: c_int = 21;
pub const NID_pkcs7_signed: c_int = 22;
pub const NID_pkcs7_enveloped: c_int = 23;
pub const NID_pkcs7_signedAndEnveloped: c_int = 24;
pub const NID_pkcs7_digest: c_int = 25;
pub const NID_pkcs7_encrypted: c_int = 26;
pub const NID_pkcs9: c_int = 47;
pub const NID_pkcs9_emailAddress: c_int = 48;
pub const NID_pkcs9_unstructuredName: c_int = 49;
pub const NID_pkcs9_contentType: c_int = 50;
pub const NID_pkcs9_messageDigest: c_int = 51;
pub const NID_pkcs9_signingTime: c_int = 52;
pub const NID_pkcs9_countersignature: c_int = 53;
pub const NID_pkcs9_challengePassword: c_int = 54;
pub const NID_pkcs9_unstructuredAddress: c_int = 55;
pub const NID_pkcs9_extCertAttributes: c_int = 56;
pub const NID_ext_req: c_int = 172;
pub const NID_SMIMECapabilities: c_int = 167;
pub const NID_SMIME: c_int = 188;
pub const NID_id_smime_mod: c_int = 189;
pub const NID_id_smime_ct: c_int = 190;
pub const NID_id_smime_aa: c_int = 191;
pub const NID_id_smime_alg: c_int = 192;
pub const NID_id_smime_cd: c_int = 193;
pub const NID_id_smime_spq: c_int = 194;
pub const NID_id_smime_cti: c_int = 195;
pub const NID_id_smime_mod_cms: c_int = 196;
pub const NID_id_smime_mod_ess: c_int = 197;
pub const NID_id_smime_mod_oid: c_int = 198;
pub const NID_id_smime_mod_msg_v3: c_int = 199;
pub const NID_id_smime_mod_ets_eSignature_88: c_int = 200;
pub const NID_id_smime_mod_ets_eSignature_97: c_int = 201;
pub const NID_id_smime_mod_ets_eSigPolicy_88: c_int = 202;
pub const NID_id_smime_mod_ets_eSigPolicy_97: c_int = 203;
pub const NID_id_smime_ct_receipt: c_int = 204;
pub const NID_id_smime_ct_authData: c_int = 205;
pub const NID_id_smime_ct_publishCert: c_int = 206;
pub const NID_id_smime_ct_TSTInfo: c_int = 207;
pub const NID_id_smime_ct_TDTInfo: c_int = 208;
pub const NID_id_smime_ct_contentInfo: c_int = 209;
pub const NID_id_smime_ct_DVCSRequestData: c_int = 210;
pub const NID_id_smime_ct_DVCSResponseData: c_int = 211;
pub const NID_id_smime_ct_compressedData: c_int = 786;
pub const NID_id_ct_asciiTextWithCRLF: c_int = 787;
pub const NID_id_smime_aa_receiptRequest: c_int = 212;
pub const NID_id_smime_aa_securityLabel: c_int = 213;
pub const NID_id_smime_aa_mlExpandHistory: c_int = 214;
pub const NID_id_smime_aa_contentHint: c_int = 215;
pub const NID_id_smime_aa_msgSigDigest: c_int = 216;
pub const NID_id_smime_aa_encapContentType: c_int = 217;
pub const NID_id_smime_aa_contentIdentifier: c_int = 218;
pub const NID_id_smime_aa_macValue: c_int = 219;
pub const NID_id_smime_aa_equivalentLabels: c_int = 220;
pub const NID_id_smime_aa_contentReference: c_int = 221;
pub const NID_id_smime_aa_encrypKeyPref: c_int = 222;
pub const NID_id_smime_aa_signingCertificate: c_int = 223;
pub const NID_id_smime_aa_smimeEncryptCerts: c_int = 224;
pub const NID_id_smime_aa_timeStampToken: c_int = 225;
pub const NID_id_smime_aa_ets_sigPolicyId: c_int = 226;
pub const NID_id_smime_aa_ets_commitmentType: c_int = 227;
pub const NID_id_smime_aa_ets_signerLocation: c_int = 228;
pub const NID_id_smime_aa_ets_signerAttr: c_int = 229;
pub const NID_id_smime_aa_ets_otherSigCert: c_int = 230;
pub const NID_id_smime_aa_ets_contentTimestamp: c_int = 231;
pub const NID_id_smime_aa_ets_CertificateRefs: c_int = 232;
pub const NID_id_smime_aa_ets_RevocationRefs: c_int = 233;
pub const NID_id_smime_aa_ets_certValues: c_int = 234;
pub const NID_id_smime_aa_ets_revocationValues: c_int = 235;
pub const NID_id_smime_aa_ets_escTimeStamp: c_int = 236;
pub const NID_id_smime_aa_ets_certCRLTimestamp: c_int = 237;
pub const NID_id_smime_aa_ets_archiveTimeStamp: c_int = 238;
pub const NID_id_smime_aa_signatureType: c_int = 239;
pub const NID_id_smime_aa_dvcs_dvc: c_int = 240;
pub const NID_id_smime_alg_ESDHwith3DES: c_int = 241;
pub const NID_id_smime_alg_ESDHwithRC2: c_int = 242;
pub const NID_id_smime_alg_3DESwrap: c_int = 243;
pub const NID_id_smime_alg_RC2wrap: c_int = 244;
pub const NID_id_smime_alg_ESDH: c_int = 245;
pub const NID_id_smime_alg_CMS3DESwrap: c_int = 246;
pub const NID_id_smime_alg_CMSRC2wrap: c_int = 247;
pub const NID_id_alg_PWRI_KEK: c_int = 893;
pub const NID_id_smime_cd_ldap: c_int = 248;
pub const NID_id_smime_spq_ets_sqt_uri: c_int = 249;
pub const NID_id_smime_spq_ets_sqt_unotice: c_int = 250;
pub const NID_id_smime_cti_ets_proofOfOrigin: c_int = 251;
pub const NID_id_smime_cti_ets_proofOfReceipt: c_int = 252;
pub const NID_id_smime_cti_ets_proofOfDelivery: c_int = 253;
pub const NID_id_smime_cti_ets_proofOfSender: c_int = 254;
pub const NID_id_smime_cti_ets_proofOfApproval: c_int = 255;
pub const NID_id_smime_cti_ets_proofOfCreation: c_int = 256;
pub const NID_friendlyName: c_int = 156;
pub const NID_localKeyID: c_int = 157;
pub const NID_ms_csp_name: c_int = 417;
pub const NID_LocalKeySet: c_int = 856;
pub const NID_x509Certificate: c_int = 158;
pub const NID_sdsiCertificate: c_int = 159;
pub const NID_x509Crl: c_int = 160;
pub const NID_pbe_WithSHA1And128BitRC4: c_int = 144;
pub const NID_pbe_WithSHA1And40BitRC4: c_int = 145;
pub const NID_pbe_WithSHA1And3_Key_TripleDES_CBC: c_int = 146;
pub const NID_pbe_WithSHA1And2_Key_TripleDES_CBC: c_int = 147;
pub const NID_pbe_WithSHA1And128BitRC2_CBC: c_int = 148;
pub const NID_pbe_WithSHA1And40BitRC2_CBC: c_int = 149;
pub const NID_keyBag: c_int = 150;
pub const NID_pkcs8ShroudedKeyBag: c_int = 151;
pub const NID_certBag: c_int = 152;
pub const NID_crlBag: c_int = 153;
pub const NID_secretBag: c_int = 154;
pub const NID_safeContentsBag: c_int = 155;
pub const NID_md2: c_int = 3;
pub const NID_md4: c_int = 257;
pub const NID_md5: c_int = 4;
pub const NID_md5_sha1: c_int = 114;
pub const NID_hmacWithMD5: c_int = 797;
pub const NID_hmacWithSHA1: c_int = 163;
pub const NID_hmacWithSHA224: c_int = 798;
pub const NID_hmacWithSHA256: c_int = 799;
pub const NID_hmacWithSHA384: c_int = 800;
pub const NID_hmacWithSHA512: c_int = 801;
pub const NID_rc2_cbc: c_int = 37;
pub const NID_rc2_ecb: c_int = 38;
pub const NID_rc2_cfb64: c_int = 39;
pub const NID_rc2_ofb64: c_int = 40;
pub const NID_rc2_40_cbc: c_int = 98;
pub const NID_rc2_64_cbc: c_int = 166;
pub const NID_rc4: c_int = 5;
pub const NID_rc4_40: c_int = 97;
pub const NID_des_ede3_cbc: c_int = 44;
pub const NID_rc5_cbc: c_int = 120;
pub const NID_rc5_ecb: c_int = 121;
pub const NID_rc5_cfb64: c_int = 122;
pub const NID_rc5_ofb64: c_int = 123;
pub const NID_ms_ext_req: c_int = 171;
pub const NID_ms_code_ind: c_int = 134;
pub const NID_ms_code_com: c_int = 135;
pub const NID_ms_ctl_sign: c_int = 136;
pub const NID_ms_sgc: c_int = 137;
pub const NID_ms_efs: c_int = 138;
pub const NID_ms_smartcard_login: c_int = 648;
pub const NID_ms_upn: c_int = 649;
pub const NID_idea_cbc: c_int = 34;
pub const NID_idea_ecb: c_int = 36;
pub const NID_idea_cfb64: c_int = 35;
pub const NID_idea_ofb64: c_int = 46;
pub const NID_bf_cbc: c_int = 91;
pub const NID_bf_ecb: c_int = 92;
pub const NID_bf_cfb64: c_int = 93;
pub const NID_bf_ofb64: c_int = 94;
pub const NID_id_pkix: c_int = 127;
pub const NID_id_pkix_mod: c_int = 258;
pub const NID_id_pe: c_int = 175;
pub const NID_id_qt: c_int = 259;
pub const NID_id_kp: c_int = 128;
pub const NID_id_it: c_int = 260;
pub const NID_id_pkip: c_int = 261;
pub const NID_id_alg: c_int = 262;
pub const NID_id_cmc: c_int = 263;
pub const NID_id_on: c_int = 264;
pub const NID_id_pda: c_int = 265;
pub const NID_id_aca: c_int = 266;
pub const NID_id_qcs: c_int = 267;
pub const NID_id_cct: c_int = 268;
pub const NID_id_ppl: c_int = 662;
pub const NID_id_ad: c_int = 176;
pub const NID_id_pkix1_explicit_88: c_int = 269;
pub const NID_id_pkix1_implicit_88: c_int = 270;
pub const NID_id_pkix1_explicit_93: c_int = 271;
pub const NID_id_pkix1_implicit_93: c_int = 272;
pub const NID_id_mod_crmf: c_int = 273;
pub const NID_id_mod_cmc: c_int = 274;
pub const NID_id_mod_kea_profile_88: c_int = 275;
pub const NID_id_mod_kea_profile_93: c_int = 276;
pub const NID_id_mod_cmp: c_int = 277;
pub const NID_id_mod_qualified_cert_88: c_int = 278;
pub const NID_id_mod_qualified_cert_93: c_int = 279;
pub const NID_id_mod_attribute_cert: c_int = 280;
pub const NID_id_mod_timestamp_protocol: c_int = 281;
pub const NID_id_mod_ocsp: c_int = 282;
pub const NID_id_mod_dvcs: c_int = 283;
pub const NID_id_mod_cmp2000: c_int = 284;
pub const NID_info_access: c_int = 177;
pub const NID_biometricInfo: c_int = 285;
pub const NID_qcStatements: c_int = 286;
pub const NID_ac_auditEntity: c_int = 287;
pub const NID_ac_targeting: c_int = 288;
pub const NID_aaControls: c_int = 289;
pub const NID_sbgp_ipAddrBlock: c_int = 290;
pub const NID_sbgp_autonomousSysNum: c_int = 291;
pub const NID_sbgp_routerIdentifier: c_int = 292;
pub const NID_ac_proxying: c_int = 397;
pub const NID_sinfo_access: c_int = 398;
pub const NID_proxyCertInfo: c_int = 663;
pub const NID_id_qt_cps: c_int = 164;
pub const NID_id_qt_unotice: c_int = 165;
pub const NID_textNotice: c_int = 293;
pub const NID_server_auth: c_int = 129;
pub const NID_client_auth: c_int = 130;
pub const NID_code_sign: c_int = 131;
pub const NID_email_protect: c_int = 132;
pub const NID_ipsecEndSystem: c_int = 294;
pub const NID_ipsecTunnel: c_int = 295;
pub const NID_ipsecUser: c_int = 296;
pub const NID_time_stamp: c_int = 133;
pub const NID_OCSP_sign: c_int = 180;
pub const NID_dvcs: c_int = 297;
pub const NID_id_it_caProtEncCert: c_int = 298;
pub const NID_id_it_signKeyPairTypes: c_int = 299;
pub const NID_id_it_encKeyPairTypes: c_int = 300;
pub const NID_id_it_preferredSymmAlg: c_int = 301;
pub const NID_id_it_caKeyUpdateInfo: c_int = 302;
pub const NID_id_it_currentCRL: c_int = 303;
pub const NID_id_it_unsupportedOIDs: c_int = 304;
pub const NID_id_it_subscriptionRequest: c_int = 305;
pub const NID_id_it_subscriptionResponse: c_int = 306;
pub const NID_id_it_keyPairParamReq: c_int = 307;
pub const NID_id_it_keyPairParamRep: c_int = 308;
pub const NID_id_it_revPassphrase: c_int = 309;
pub const NID_id_it_implicitConfirm: c_int = 310;
pub const NID_id_it_confirmWaitTime: c_int = 311;
pub const NID_id_it_origPKIMessage: c_int = 312;
pub const NID_id_it_suppLangTags: c_int = 784;
pub const NID_id_regCtrl: c_int = 313;
pub const NID_id_regInfo: c_int = 314;
pub const NID_id_regCtrl_regToken: c_int = 315;
pub const NID_id_regCtrl_authenticator: c_int = 316;
pub const NID_id_regCtrl_pkiPublicationInfo: c_int = 317;
pub const NID_id_regCtrl_pkiArchiveOptions: c_int = 318;
pub const NID_id_regCtrl_oldCertID: c_int = 319;
pub const NID_id_regCtrl_protocolEncrKey: c_int = 320;
pub const NID_id_regInfo_utf8Pairs: c_int = 321;
pub const NID_id_regInfo_certReq: c_int = 322;
pub const NID_id_alg_des40: c_int = 323;
pub const NID_id_alg_noSignature: c_int = 324;
pub const NID_id_alg_dh_sig_hmac_sha1: c_int = 325;
pub const NID_id_alg_dh_pop: c_int = 326;
pub const NID_id_cmc_statusInfo: c_int = 327;
pub const NID_id_cmc_identification: c_int = 328;
pub const NID_id_cmc_identityProof: c_int = 329;
pub const NID_id_cmc_dataReturn: c_int = 330;
pub const NID_id_cmc_transactionId: c_int = 331;
pub const NID_id_cmc_senderNonce: c_int = 332;
pub const NID_id_cmc_recipientNonce: c_int = 333;
pub const NID_id_cmc_addExtensions: c_int = 334;
pub const NID_id_cmc_encryptedPOP: c_int = 335;
pub const NID_id_cmc_decryptedPOP: c_int = 336;
pub const NID_id_cmc_lraPOPWitness: c_int = 337;
pub const NID_id_cmc_getCert: c_int = 338;
pub const NID_id_cmc_getCRL: c_int = 339;
pub const NID_id_cmc_revokeRequest: c_int = 340;
pub const NID_id_cmc_regInfo: c_int = 341;
pub const NID_id_cmc_responseInfo: c_int = 342;
pub const NID_id_cmc_queryPending: c_int = 343;
pub const NID_id_cmc_popLinkRandom: c_int = 344;
pub const NID_id_cmc_popLinkWitness: c_int = 345;
pub const NID_id_cmc_confirmCertAcceptance: c_int = 346;
pub const NID_id_on_personalData: c_int = 347;
pub const NID_id_on_permanentIdentifier: c_int = 858;
pub const NID_id_pda_dateOfBirth: c_int = 348;
pub const NID_id_pda_placeOfBirth: c_int = 349;
pub const NID_id_pda_gender: c_int = 351;
pub const NID_id_pda_countryOfCitizenship: c_int = 352;
pub const NID_id_pda_countryOfResidence: c_int = 353;
pub const NID_id_aca_authenticationInfo: c_int = 354;
pub const NID_id_aca_accessIdentity: c_int = 355;
pub const NID_id_aca_chargingIdentity: c_int = 356;
pub const NID_id_aca_group: c_int = 357;
pub const NID_id_aca_role: c_int = 358;
pub const NID_id_aca_encAttrs: c_int = 399;
pub const NID_id_qcs_pkixQCSyntax_v1: c_int = 359;
pub const NID_id_cct_crs: c_int = 360;
pub const NID_id_cct_PKIData: c_int = 361;
pub const NID_id_cct_PKIResponse: c_int = 362;
pub const NID_id_ppl_anyLanguage: c_int = 664;
pub const NID_id_ppl_inheritAll: c_int = 665;
pub const NID_Independent: c_int = 667;
pub const NID_ad_OCSP: c_int = 178;
pub const NID_ad_ca_issuers: c_int = 179;
pub const NID_ad_timeStamping: c_int = 363;
pub const NID_ad_dvcs: c_int = 364;
pub const NID_caRepository: c_int = 785;
pub const NID_id_pkix_OCSP_basic: c_int = 365;
pub const NID_id_pkix_OCSP_Nonce: c_int = 366;
pub const NID_id_pkix_OCSP_CrlID: c_int = 367;
pub const NID_id_pkix_OCSP_acceptableResponses: c_int = 368;
pub const NID_id_pkix_OCSP_noCheck: c_int = 369;
pub const NID_id_pkix_OCSP_archiveCutoff: c_int = 370;
pub const NID_id_pkix_OCSP_serviceLocator: c_int = 371;
pub const NID_id_pkix_OCSP_extendedStatus: c_int = 372;
pub const NID_id_pkix_OCSP_valid: c_int = 373;
pub const NID_id_pkix_OCSP_path: c_int = 374;
pub const NID_id_pkix_OCSP_trustRoot: c_int = 375;
pub const NID_algorithm: c_int = 376;
pub const NID_md5WithRSA: c_int = 104;
pub const NID_des_ecb: c_int = 29;
pub const NID_des_cbc: c_int = 31;
pub const NID_des_ofb64: c_int = 45;
pub const NID_des_cfb64: c_int = 30;
pub const NID_rsaSignature: c_int = 377;
pub const NID_dsa_2: c_int = 67;
pub const NID_dsaWithSHA: c_int = 66;
pub const NID_shaWithRSAEncryption: c_int = 42;
pub const NID_des_ede_ecb: c_int = 32;
pub const NID_des_ede3_ecb: c_int = 33;
pub const NID_des_ede_cbc: c_int = 43;
pub const NID_des_ede_cfb64: c_int = 60;
pub const NID_des_ede3_cfb64: c_int = 61;
pub const NID_des_ede_ofb64: c_int = 62;
pub const NID_des_ede3_ofb64: c_int = 63;
pub const NID_desx_cbc: c_int = 80;
pub const NID_sha: c_int = 41;
pub const NID_sha1: c_int = 64;
pub const NID_dsaWithSHA1_2: c_int = 70;
pub const NID_sha1WithRSA: c_int = 115;
pub const NID_ripemd160: c_int = 117;
pub const NID_ripemd160WithRSA: c_int = 119;
pub const NID_sxnet: c_int = 143;
pub const NID_X500: c_int = 11;
pub const NID_X509: c_int = 12;
pub const NID_commonName: c_int = 13;
pub const NID_surname: c_int = 100;
pub const NID_serialNumber: c_int = 105;
pub const NID_countryName: c_int = 14;
pub const NID_localityName: c_int = 15;
pub const NID_stateOrProvinceName: c_int = 16;
pub const NID_streetAddress: c_int = 660;
pub const NID_organizationName: c_int = 17;
pub const NID_organizationalUnitName: c_int = 18;
pub const NID_title: c_int = 106;
pub const NID_description: c_int = 107;
pub const NID_searchGuide: c_int = 859;
pub const NID_businessCategory: c_int = 860;
pub const NID_postalAddress: c_int = 861;
pub const NID_postalCode: c_int = 661;
pub const NID_postOfficeBox: c_int = 862;
pub const NID_physicalDeliveryOfficeName: c_int = 863;
pub const NID_telephoneNumber: c_int = 864;
pub const NID_telexNumber: c_int = 865;
pub const NID_teletexTerminalIdentifier: c_int = 866;
pub const NID_facsimileTelephoneNumber: c_int = 867;
pub const NID_x121Address: c_int = 868;
pub const NID_internationaliSDNNumber: c_int = 869;
pub const NID_registeredAddress: c_int = 870;
pub const NID_destinationIndicator: c_int = 871;
pub const NID_preferredDeliveryMethod: c_int = 872;
pub const NID_presentationAddress: c_int = 873;
pub const NID_supportedApplicationContext: c_int = 874;
pub const NID_member: c_int = 875;
pub const NID_owner: c_int = 876;
pub const NID_roleOccupant: c_int = 877;
pub const NID_seeAlso: c_int = 878;
pub const NID_userPassword: c_int = 879;
pub const NID_userCertificate: c_int = 880;
pub const NID_cACertificate: c_int = 881;
pub const NID_authorityRevocationList: c_int = 882;
pub const NID_certificateRevocationList: c_int = 883;
pub const NID_crossCertificatePair: c_int = 884;
pub const NID_name: c_int = 173;
pub const NID_givenName: c_int = 99;
pub const NID_initials: c_int = 101;
pub const NID_generationQualifier: c_int = 509;
pub const NID_x500UniqueIdentifier: c_int = 503;
pub const NID_dnQualifier: c_int = 174;
pub const NID_enhancedSearchGuide: c_int = 885;
pub const NID_protocolInformation: c_int = 886;
pub const NID_distinguishedName: c_int = 887;
pub const NID_uniqueMember: c_int = 888;
pub const NID_houseIdentifier: c_int = 889;
pub const NID_supportedAlgorithms: c_int = 890;
pub const NID_deltaRevocationList: c_int = 891;
pub const NID_dmdName: c_int = 892;
pub const NID_pseudonym: c_int = 510;
pub const NID_role: c_int = 400;
pub const NID_X500algorithms: c_int = 378;
pub const NID_rsa: c_int = 19;
pub const NID_mdc2WithRSA: c_int = 96;
pub const NID_mdc2: c_int = 95;
pub const NID_id_ce: c_int = 81;
pub const NID_subject_directory_attributes: c_int = 769;
pub const NID_subject_key_identifier: c_int = 82;
pub const NID_key_usage: c_int = 83;
pub const NID_private_key_usage_period: c_int = 84;
pub const NID_subject_alt_name: c_int = 85;
pub const NID_issuer_alt_name: c_int = 86;
pub const NID_basic_constraints: c_int = 87;
pub const NID_crl_number: c_int = 88;
pub const NID_crl_reason: c_int = 141;
pub const NID_invalidity_date: c_int = 142;
pub const NID_delta_crl: c_int = 140;
pub const NID_issuing_distribution_point: c_int = 770;
pub const NID_certificate_issuer: c_int = 771;
pub const NID_name_constraints: c_int = 666;
pub const NID_crl_distribution_points: c_int = 103;
pub const NID_certificate_policies: c_int = 89;
pub const NID_any_policy: c_int = 746;
pub const NID_policy_mappings: c_int = 747;
pub const NID_authority_key_identifier: c_int = 90;
pub const NID_policy_constraints: c_int = 401;
pub const NID_ext_key_usage: c_int = 126;
pub const NID_freshest_crl: c_int = 857;
pub const NID_inhibit_any_policy: c_int = 748;
pub const NID_target_information: c_int = 402;
pub const NID_no_rev_avail: c_int = 403;
pub const NID_anyExtendedKeyUsage: c_int = 910;
pub const NID_netscape: c_int = 57;
pub const NID_netscape_cert_extension: c_int = 58;
pub const NID_netscape_data_type: c_int = 59;
pub const NID_netscape_cert_type: c_int = 71;
pub const NID_netscape_base_url: c_int = 72;
pub const NID_netscape_revocation_url: c_int = 73;
pub const NID_netscape_ca_revocation_url: c_int = 74;
pub const NID_netscape_renewal_url: c_int = 75;
pub const NID_netscape_ca_policy_url: c_int = 76;
pub const NID_netscape_ssl_server_name: c_int = 77;
pub const NID_netscape_comment: c_int = 78;
pub const NID_netscape_cert_sequence: c_int = 79;
pub const NID_ns_sgc: c_int = 139;
pub const NID_org: c_int = 379;
pub const NID_dod: c_int = 380;
pub const NID_iana: c_int = 381;
pub const NID_Directory: c_int = 382;
pub const NID_Management: c_int = 383;
pub const NID_Experimental: c_int = 384;
pub const NID_Private: c_int = 385;
pub const NID_Security: c_int = 386;
pub const NID_SNMPv2: c_int = 387;
pub const NID_Mail: c_int = 388;
pub const NID_Enterprises: c_int = 389;
pub const NID_dcObject: c_int = 390;
pub const NID_mime_mhs: c_int = 504;
pub const NID_mime_mhs_headings: c_int = 505;
pub const NID_mime_mhs_bodies: c_int = 506;
pub const NID_id_hex_partial_message: c_int = 507;
pub const NID_id_hex_multipart_message: c_int = 508;
pub const NID_zlib_compression: c_int = 125;
pub const NID_aes_128_ecb: c_int = 418;
pub const NID_aes_128_cbc: c_int = 419;
pub const NID_aes_128_ofb128: c_int = 420;
pub const NID_aes_128_cfb128: c_int = 421;
pub const NID_id_aes128_wrap: c_int = 788;
pub const NID_aes_128_gcm: c_int = 895;
pub const NID_aes_128_ccm: c_int = 896;
pub const NID_id_aes128_wrap_pad: c_int = 897;
pub const NID_aes_192_ecb: c_int = 422;
pub const NID_aes_192_cbc: c_int = 423;
pub const NID_aes_192_ofb128: c_int = 424;
pub const NID_aes_192_cfb128: c_int = 425;
pub const NID_id_aes192_wrap: c_int = 789;
pub const NID_aes_192_gcm: c_int = 898;
pub const NID_aes_192_ccm: c_int = 899;
pub const NID_id_aes192_wrap_pad: c_int = 900;
pub const NID_aes_256_ecb: c_int = 426;
pub const NID_aes_256_cbc: c_int = 427;
pub const NID_aes_256_ofb128: c_int = 428;
pub const NID_aes_256_cfb128: c_int = 429;
pub const NID_id_aes256_wrap: c_int = 790;
pub const NID_aes_256_gcm: c_int = 901;
pub const NID_aes_256_ccm: c_int = 902;
pub const NID_id_aes256_wrap_pad: c_int = 903;
pub const NID_aes_128_cfb1: c_int = 650;
pub const NID_aes_192_cfb1: c_int = 651;
pub const NID_aes_256_cfb1: c_int = 652;
pub const NID_aes_128_cfb8: c_int = 653;
pub const NID_aes_192_cfb8: c_int = 654;
pub const NID_aes_256_cfb8: c_int = 655;
pub const NID_aes_128_ctr: c_int = 904;
pub const NID_aes_192_ctr: c_int = 905;
pub const NID_aes_256_ctr: c_int = 906;
pub const NID_aes_128_xts: c_int = 913;
pub const NID_aes_256_xts: c_int = 914;
pub const NID_des_cfb1: c_int = 656;
pub const NID_des_cfb8: c_int = 657;
pub const NID_des_ede3_cfb1: c_int = 658;
pub const NID_des_ede3_cfb8: c_int = 659;
pub const NID_sha256: c_int = 672;
pub const NID_sha384: c_int = 673;
pub const NID_sha512: c_int = 674;
pub const NID_sha224: c_int = 675;
pub const NID_dsa_with_SHA224: c_int = 802;
pub const NID_dsa_with_SHA256: c_int = 803;
pub const NID_hold_instruction_code: c_int = 430;
pub const NID_hold_instruction_none: c_int = 431;
pub const NID_hold_instruction_call_issuer: c_int = 432;
pub const NID_hold_instruction_reject: c_int = 433;
pub const NID_data: c_int = 434;
pub const NID_pss: c_int = 435;
pub const NID_ucl: c_int = 436;
pub const NID_pilot: c_int = 437;
pub const NID_pilotAttributeType: c_int = 438;
pub const NID_pilotAttributeSyntax: c_int = 439;
pub const NID_pilotObjectClass: c_int = 440;
pub const NID_pilotGroups: c_int = 441;
pub const NID_iA5StringSyntax: c_int = 442;
pub const NID_caseIgnoreIA5StringSyntax: c_int = 443;
pub const NID_pilotObject: c_int = 444;
pub const NID_pilotPerson: c_int = 445;
pub const NID_account: c_int = 446;
pub const NID_document: c_int = 447;
pub const NID_room: c_int = 448;
pub const NID_documentSeries: c_int = 449;
pub const NID_Domain: c_int = 392;
pub const NID_rFC822localPart: c_int = 450;
pub const NID_dNSDomain: c_int = 451;
pub const NID_domainRelatedObject: c_int = 452;
pub const NID_friendlyCountry: c_int = 453;
pub const NID_simpleSecurityObject: c_int = 454;
pub const NID_pilotOrganization: c_int = 455;
pub const NID_pilotDSA: c_int = 456;
pub const NID_qualityLabelledData: c_int = 457;
pub const NID_userId: c_int = 458;
pub const NID_textEncodedORAddress: c_int = 459;
pub const NID_rfc822Mailbox: c_int = 460;
pub const NID_info: c_int = 461;
pub const NID_favouriteDrink: c_int = 462;
pub const NID_roomNumber: c_int = 463;
pub const NID_photo: c_int = 464;
pub const NID_userClass: c_int = 465;
pub const NID_host: c_int = 466;
pub const NID_manager: c_int = 467;
pub const NID_documentIdentifier: c_int = 468;
pub const NID_documentTitle: c_int = 469;
pub const NID_documentVersion: c_int = 470;
pub const NID_documentAuthor: c_int = 471;
pub const NID_documentLocation: c_int = 472;
pub const NID_homeTelephoneNumber: c_int = 473;
pub const NID_secretary: c_int = 474;
pub const NID_otherMailbox: c_int = 475;
pub const NID_lastModifiedTime: c_int = 476;
pub const NID_lastModifiedBy: c_int = 477;
pub const NID_domainComponent: c_int = 391;
pub const NID_aRecord: c_int = 478;
pub const NID_pilotAttributeType27: c_int = 479;
pub const NID_mXRecord: c_int = 480;
pub const NID_nSRecord: c_int = 481;
pub const NID_sOARecord: c_int = 482;
pub const NID_cNAMERecord: c_int = 483;
pub const NID_associatedDomain: c_int = 484;
pub const NID_associatedName: c_int = 485;
pub const NID_homePostalAddress: c_int = 486;
pub const NID_personalTitle: c_int = 487;
pub const NID_mobileTelephoneNumber: c_int = 488;
pub const NID_pagerTelephoneNumber: c_int = 489;
pub const NID_friendlyCountryName: c_int = 490;
pub const NID_organizationalStatus: c_int = 491;
pub const NID_janetMailbox: c_int = 492;
pub const NID_mailPreferenceOption: c_int = 493;
pub const NID_buildingName: c_int = 494;
pub const NID_dSAQuality: c_int = 495;
pub const NID_singleLevelQuality: c_int = 496;
pub const NID_subtreeMinimumQuality: c_int = 497;
pub const NID_subtreeMaximumQuality: c_int = 498;
pub const NID_personalSignature: c_int = 499;
pub const NID_dITRedirect: c_int = 500;
pub const NID_audio: c_int = 501;
pub const NID_documentPublisher: c_int = 502;
pub const NID_id_set: c_int = 512;
pub const NID_set_ctype: c_int = 513;
pub const NID_set_msgExt: c_int = 514;
pub const NID_set_attr: c_int = 515;
pub const NID_set_policy: c_int = 516;
pub const NID_set_certExt: c_int = 517;
pub const NID_set_brand: c_int = 518;
pub const NID_setct_PANData: c_int = 519;
pub const NID_setct_PANToken: c_int = 520;
pub const NID_setct_PANOnly: c_int = 521;
pub const NID_setct_OIData: c_int = 522;
pub const NID_setct_PI: c_int = 523;
pub const NID_setct_PIData: c_int = 524;
pub const NID_setct_PIDataUnsigned: c_int = 525;
pub const NID_setct_HODInput: c_int = 526;
pub const NID_setct_AuthResBaggage: c_int = 527;
pub const NID_setct_AuthRevReqBaggage: c_int = 528;
pub const NID_setct_AuthRevResBaggage: c_int = 529;
pub const NID_setct_CapTokenSeq: c_int = 530;
pub const NID_setct_PInitResData: c_int = 531;
pub const NID_setct_PI_TBS: c_int = 532;
pub const NID_setct_PResData: c_int = 533;
pub const NID_setct_AuthReqTBS: c_int = 534;
pub const NID_setct_AuthResTBS: c_int = 535;
pub const NID_setct_AuthResTBSX: c_int = 536;
pub const NID_setct_AuthTokenTBS: c_int = 537;
pub const NID_setct_CapTokenData: c_int = 538;
pub const NID_setct_CapTokenTBS: c_int = 539;
pub const NID_setct_AcqCardCodeMsg: c_int = 540;
pub const NID_setct_AuthRevReqTBS: c_int = 541;
pub const NID_setct_AuthRevResData: c_int = 542;
pub const NID_setct_AuthRevResTBS: c_int = 543;
pub const NID_setct_CapReqTBS: c_int = 544;
pub const NID_setct_CapReqTBSX: c_int = 545;
pub const NID_setct_CapResData: c_int = 546;
pub const NID_setct_CapRevReqTBS: c_int = 547;
pub const NID_setct_CapRevReqTBSX: c_int = 548;
pub const NID_setct_CapRevResData: c_int = 549;
pub const NID_setct_CredReqTBS: c_int = 550;
pub const NID_setct_CredReqTBSX: c_int = 551;
pub const NID_setct_CredResData: c_int = 552;
pub const NID_setct_CredRevReqTBS: c_int = 553;
pub const NID_setct_CredRevReqTBSX: c_int = 554;
pub const NID_setct_CredRevResData: c_int = 555;
pub const NID_setct_PCertReqData: c_int = 556;
pub const NID_setct_PCertResTBS: c_int = 557;
pub const NID_setct_BatchAdminReqData: c_int = 558;
pub const NID_setct_BatchAdminResData: c_int = 559;
pub const NID_setct_CardCInitResTBS: c_int = 560;
pub const NID_setct_MeAqCInitResTBS: c_int = 561;
pub const NID_setct_RegFormResTBS: c_int = 562;
pub const NID_setct_CertReqData: c_int = 563;
pub const NID_setct_CertReqTBS: c_int = 564;
pub const NID_setct_CertResData: c_int = 565;
pub const NID_setct_CertInqReqTBS: c_int = 566;
pub const NID_setct_ErrorTBS: c_int = 567;
pub const NID_setct_PIDualSignedTBE: c_int = 568;
pub const NID_setct_PIUnsignedTBE: c_int = 569;
pub const NID_setct_AuthReqTBE: c_int = 570;
pub const NID_setct_AuthResTBE: c_int = 571;
pub const NID_setct_AuthResTBEX: c_int = 572;
pub const NID_setct_AuthTokenTBE: c_int = 573;
pub const NID_setct_CapTokenTBE: c_int = 574;
pub const NID_setct_CapTokenTBEX: c_int = 575;
pub const NID_setct_AcqCardCodeMsgTBE: c_int = 576;
pub const NID_setct_AuthRevReqTBE: c_int = 577;
pub const NID_setct_AuthRevResTBE: c_int = 578;
pub const NID_setct_AuthRevResTBEB: c_int = 579;
pub const NID_setct_CapReqTBE: c_int = 580;
pub const NID_setct_CapReqTBEX: c_int = 581;
pub const NID_setct_CapResTBE: c_int = 582;
pub const NID_setct_CapRevReqTBE: c_int = 583;
pub const NID_setct_CapRevReqTBEX: c_int = 584;
pub const NID_setct_CapRevResTBE: c_int = 585;
pub const NID_setct_CredReqTBE: c_int = 586;
pub const NID_setct_CredReqTBEX: c_int = 587;
pub const NID_setct_CredResTBE: c_int = 588;
pub const NID_setct_CredRevReqTBE: c_int = 589;
pub const NID_setct_CredRevReqTBEX: c_int = 590;
pub const NID_setct_CredRevResTBE: c_int = 591;
pub const NID_setct_BatchAdminReqTBE: c_int = 592;
pub const NID_setct_BatchAdminResTBE: c_int = 593;
pub const NID_setct_RegFormReqTBE: c_int = 594;
pub const NID_setct_CertReqTBE: c_int = 595;
pub const NID_setct_CertReqTBEX: c_int = 596;
pub const NID_setct_CertResTBE: c_int = 597;
pub const NID_setct_CRLNotificationTBS: c_int = 598;
pub const NID_setct_CRLNotificationResTBS: c_int = 599;
pub const NID_setct_BCIDistributionTBS: c_int = 600;
pub const NID_setext_genCrypt: c_int = 601;
pub const NID_setext_miAuth: c_int = 602;
pub const NID_setext_pinSecure: c_int = 603;
pub const NID_setext_pinAny: c_int = 604;
pub const NID_setext_track2: c_int = 605;
pub const NID_setext_cv: c_int = 606;
pub const NID_set_policy_root: c_int = 607;
pub const NID_setCext_hashedRoot: c_int = 608;
pub const NID_setCext_certType: c_int = 609;
pub const NID_setCext_merchData: c_int = 610;
pub const NID_setCext_cCertRequired: c_int = 611;
pub const NID_setCext_tunneling: c_int = 612;
pub const NID_setCext_setExt: c_int = 613;
pub const NID_setCext_setQualf: c_int = 614;
pub const NID_setCext_PGWYcapabilities: c_int = 615;
pub const NID_setCext_TokenIdentifier: c_int = 616;
pub const NID_setCext_Track2Data: c_int = 617;
pub const NID_setCext_TokenType: c_int = 618;
pub const NID_setCext_IssuerCapabilities: c_int = 619;
pub const NID_setAttr_Cert: c_int = 620;
pub const NID_setAttr_PGWYcap: c_int = 621;
pub const NID_setAttr_TokenType: c_int = 622;
pub const NID_setAttr_IssCap: c_int = 623;
pub const NID_set_rootKeyThumb: c_int = 624;
pub const NID_set_addPolicy: c_int = 625;
pub const NID_setAttr_Token_EMV: c_int = 626;
pub const NID_setAttr_Token_B0Prime: c_int = 627;
pub const NID_setAttr_IssCap_CVM: c_int = 628;
pub const NID_setAttr_IssCap_T2: c_int = 629;
pub const NID_setAttr_IssCap_Sig: c_int = 630;
pub const NID_setAttr_GenCryptgrm: c_int = 631;
pub const NID_setAttr_T2Enc: c_int = 632;
pub const NID_setAttr_T2cleartxt: c_int = 633;
pub const NID_setAttr_TokICCsig: c_int = 634;
pub const NID_setAttr_SecDevSig: c_int = 635;
pub const NID_set_brand_IATA_ATA: c_int = 636;
pub const NID_set_brand_Diners: c_int = 637;
pub const NID_set_brand_AmericanExpress: c_int = 638;
pub const NID_set_brand_JCB: c_int = 639;
pub const NID_set_brand_Visa: c_int = 640;
pub const NID_set_brand_MasterCard: c_int = 641;
pub const NID_set_brand_Novus: c_int = 642;
pub const NID_des_cdmf: c_int = 643;
pub const NID_rsaOAEPEncryptionSET: c_int = 644;
pub const NID_ipsec3: c_int = 749;
pub const NID_ipsec4: c_int = 750;
pub const NID_whirlpool: c_int = 804;
pub const NID_cryptopro: c_int = 805;
pub const NID_cryptocom: c_int = 806;
pub const NID_id_GostR3411_94_with_GostR3410_2001: c_int = 807;
pub const NID_id_GostR3411_94_with_GostR3410_94: c_int = 808;
pub const NID_id_GostR3411_94: c_int = 809;
pub const NID_id_HMACGostR3411_94: c_int = 810;
pub const NID_id_GostR3410_2001: c_int = 811;
pub const NID_id_GostR3410_94: c_int = 812;
pub const NID_id_Gost28147_89: c_int = 813;
pub const NID_gost89_cnt: c_int = 814;
pub const NID_id_Gost28147_89_MAC: c_int = 815;
pub const NID_id_GostR3411_94_prf: c_int = 816;
pub const NID_id_GostR3410_2001DH: c_int = 817;
pub const NID_id_GostR3410_94DH: c_int = 818;
pub const NID_id_Gost28147_89_CryptoPro_KeyMeshing: c_int = 819;
pub const NID_id_Gost28147_89_None_KeyMeshing: c_int = 820;
pub const NID_id_GostR3411_94_TestParamSet: c_int = 821;
pub const NID_id_GostR3411_94_CryptoProParamSet: c_int = 822;
pub const NID_id_Gost28147_89_TestParamSet: c_int = 823;
pub const NID_id_Gost28147_89_CryptoPro_A_ParamSet: c_int = 824;
pub const NID_id_Gost28147_89_CryptoPro_B_ParamSet: c_int = 825;
pub const NID_id_Gost28147_89_CryptoPro_C_ParamSet: c_int = 826;
pub const NID_id_Gost28147_89_CryptoPro_D_ParamSet: c_int = 827;
pub const NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet: c_int = 828;
pub const NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet: c_int = 829;
pub const NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet: c_int = 830;
pub const NID_id_GostR3410_94_TestParamSet: c_int = 831;
pub const NID_id_GostR3410_94_CryptoPro_A_ParamSet: c_int = 832;
pub const NID_id_GostR3410_94_CryptoPro_B_ParamSet: c_int = 833;
pub const NID_id_GostR3410_94_CryptoPro_C_ParamSet: c_int = 834;
pub const NID_id_GostR3410_94_CryptoPro_D_ParamSet: c_int = 835;
pub const NID_id_GostR3410_94_CryptoPro_XchA_ParamSet: c_int = 836;
pub const NID_id_GostR3410_94_CryptoPro_XchB_ParamSet: c_int = 837;
pub const NID_id_GostR3410_94_CryptoPro_XchC_ParamSet: c_int = 838;
pub const NID_id_GostR3410_2001_TestParamSet: c_int = 839;
pub const NID_id_GostR3410_2001_CryptoPro_A_ParamSet: c_int = 840;
pub const NID_id_GostR3410_2001_CryptoPro_B_ParamSet: c_int = 841;
pub const NID_id_GostR3410_2001_CryptoPro_C_ParamSet: c_int = 842;
pub const NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet: c_int = 843;
pub const NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet: c_int = 844;
pub const NID_id_GostR3410_94_a: c_int = 845;
pub const NID_id_GostR3410_94_aBis: c_int = 846;
pub const NID_id_GostR3410_94_b: c_int = 847;
pub const NID_id_GostR3410_94_bBis: c_int = 848;
pub const NID_id_Gost28147_89_cc: c_int = 849;
pub const NID_id_GostR3410_94_cc: c_int = 850;
pub const NID_id_GostR3410_2001_cc: c_int = 851;
pub const NID_id_GostR3411_94_with_GostR3410_94_cc: c_int = 852;
pub const NID_id_GostR3411_94_with_GostR3410_2001_cc: c_int = 853;
pub const NID_id_GostR3410_2001_ParamSet_cc: c_int = 854;
pub const NID_camellia_128_cbc: c_int = 751;
pub const NID_camellia_192_cbc: c_int = 752;
pub const NID_camellia_256_cbc: c_int = 753;
pub const NID_id_camellia128_wrap: c_int = 907;
pub const NID_id_camellia192_wrap: c_int = 908;
pub const NID_id_camellia256_wrap: c_int = 909;
pub const NID_camellia_128_ecb: c_int = 754;
pub const NID_camellia_128_ofb128: c_int = 766;
pub const NID_camellia_128_cfb128: c_int = 757;
pub const NID_camellia_192_ecb: c_int = 755;
pub const NID_camellia_192_ofb128: c_int = 767;
pub const NID_camellia_192_cfb128: c_int = 758;
pub const NID_camellia_256_ecb: c_int = 756;
pub const NID_camellia_256_ofb128: c_int = 768;
pub const NID_camellia_256_cfb128: c_int = 759;
pub const NID_camellia_128_cfb1: c_int = 760;
pub const NID_camellia_192_cfb1: c_int = 761;
pub const NID_camellia_256_cfb1: c_int = 762;
pub const NID_camellia_128_cfb8: c_int = 763;
pub const NID_camellia_192_cfb8: c_int = 764;
pub const NID_camellia_256_cfb8: c_int = 765;
pub const NID_kisa: c_int = 773;
pub const NID_seed_ecb: c_int = 776;
pub const NID_seed_cbc: c_int = 777;
pub const NID_seed_cfb128: c_int = 779;
pub const NID_seed_ofb128: c_int = 778;
pub const NID_hmac: c_int = 855;
pub const NID_cmac: c_int = 894;
pub const NID_rc4_hmac_md5: c_int = 915;
pub const NID_aes_128_cbc_hmac_sha1: c_int = 916;
pub const NID_aes_192_cbc_hmac_sha1: c_int = 917;
pub const NID_aes_256_cbc_hmac_sha1: c_int = 918;

pub const PKCS5_SALT_LEN: c_int = 8;

pub const RSA_F4: c_long = 0x10001;

pub const RSA_PKCS1_PADDING: c_int = 1;
pub const RSA_SSLV23_PADDING: c_int = 2;
pub const RSA_NO_PADDING: c_int = 3;
pub const RSA_PKCS1_OAEP_PADDING: c_int = 4;
pub const RSA_X931_PADDING: c_int = 5;

pub const SSL_CTRL_SET_TMP_DH: c_int = 3;
pub const SSL_CTRL_SET_TMP_ECDH: c_int = 4;
pub const SSL_CTRL_EXTRA_CHAIN_CERT: c_int = 14;
pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:  c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;

pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x2;
pub const SSL_MODE_AUTO_RETRY: c_long = 0x4;
pub const SSL_MODE_NO_AUTO_CHAIN: c_long = 0x8;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x10;
pub const SSL_MODE_SEND_CLIENTHELLO_TIME: c_long = 0x20;
pub const SSL_MODE_SEND_SERVERHELLO_TIME: c_long = 0x40;
pub const SSL_MODE_SEND_FALLBACK_SCSV: c_long = 0x80;

pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;

#[cfg(not(ossl101))]
pub const SSL_OP_TLSEXT_PADDING: c_ulong =                          0x00000010;
pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: c_ulong =             0x00000800;
pub const SSL_OP_ALL: c_ulong =                                     0x80000BFF;
pub const SSL_OP_NO_QUERY_MTU: c_ulong =                            0x00001000;
pub const SSL_OP_COOKIE_EXCHANGE: c_ulong =                         0x00002000;
pub const SSL_OP_NO_TICKET: c_ulong =                               0x00004000;
pub const SSL_OP_CISCO_ANYCONNECT: c_ulong =                        0x00008000;
pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: c_ulong =  0x00010000;
pub const SSL_OP_NO_COMPRESSION: c_ulong =                          0x00020000;
pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_ulong =       0x00040000;
pub const SSL_OP_CIPHER_SERVER_PREFERENCE: c_ulong =                0x00400000;
pub const SSL_OP_TLS_ROLLBACK_BUG: c_ulong =                        0x00800000;
pub const SSL_OP_NO_SSLv3: c_ulong =                                0x02000000;
pub const SSL_OP_NO_TLSv1: c_ulong =                                0x04000000;
pub const SSL_OP_NO_TLSv1_2: c_ulong =                              0x08000000;
pub const SSL_OP_NO_TLSv1_1: c_ulong =                              0x10000000;

#[cfg(not(ossl101))]
pub const SSL_OP_NO_DTLSv1: c_ulong =                               0x04000000;
#[cfg(not(ossl101))]
pub const SSL_OP_NO_DTLSv1_2: c_ulong =                             0x08000000;
#[cfg(not(ossl101))]
pub const SSL_OP_NO_SSL_MASK: c_ulong = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;

pub const TLSEXT_NAMETYPE_host_name: c_int = 0;

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

pub const OPENSSL_NPN_UNSUPPORTED: c_int = 0;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;
pub const OPENSSL_NPN_NO_OVERLAP: c_int = 2;

pub const V_ASN1_GENERALIZEDTIME: c_int = 24;
pub const V_ASN1_UTCTIME:         c_int = 23;

pub const X509_FILETYPE_ASN1: c_int = 2;
pub const X509_FILETYPE_DEFAULT: c_int = 3;
pub const X509_FILETYPE_PEM: c_int = 1;
pub const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
pub const X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
pub const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
pub const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
pub const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
pub const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
pub const X509_V_ERR_CERT_REJECTED: c_int = 28;
pub const X509_V_ERR_CERT_REVOKED: c_int = 23;
pub const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
pub const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
pub const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
pub const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
pub const X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
pub const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
pub const X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
pub const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
pub const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
pub const X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
pub const X509_V_ERR_INVALID_CA: c_int = 24;
pub const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
pub const X509_V_ERR_INVALID_NON_CA: c_int = 37;
pub const X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
pub const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
pub const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
pub const X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
pub const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
pub const X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
pub const X509_V_ERR_OUT_OF_MEM: c_int = 17;
pub const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
pub const X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
pub const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
pub const X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
pub const X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
pub const X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
pub const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
pub const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
pub const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
pub const X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
pub const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
pub const X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
pub const X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
pub const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
pub const X509_V_OK: c_int = 0;

#[cfg(not(ossl101))]
pub const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT: c_uint = 0x1;
#[cfg(not(ossl101))]
pub const X509_CHECK_FLAG_NO_WILDCARDS: c_uint = 0x2;
#[cfg(not(ossl101))]
pub const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS: c_uint = 0x4;
#[cfg(not(ossl101))]
pub const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS: c_uint = 0x8;
#[cfg(not(ossl101))]
pub const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS: c_uint = 0x10;

pub const GEN_OTHERNAME: c_int = 0;
pub const GEN_EMAIL: c_int = 1;
pub const GEN_DNS: c_int = 2;
pub const GEN_X400: c_int = 3;
pub const GEN_DIRNAME: c_int = 4;
pub const GEN_EDIPARTY: c_int = 5;
pub const GEN_URI: c_int = 6;
pub const GEN_IPADD: c_int = 7;
pub const GEN_RID: c_int = 8;

// macros
pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    BIO_ctrl(b, BIO_CTRL_INFO, 0, pp as *mut c_void)
}

pub unsafe fn BIO_clear_retry_flags(b: *mut BIO) {
    BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_read(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_write(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_tmp_dh(ctx: *mut SSL_CTX, dh: *mut DH) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tmp_ecdh(ctx: *mut SSL_CTX, key: *mut EC_KEY) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, key as *mut c_void)
}

pub unsafe fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509 as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tlsext_servername_callback(ctx: *mut SSL_CTX,
                                                     cb: Option<extern "C" fn()>)
                                                     -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb)
}

pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *mut c_char) -> c_long {
    SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME,
             TLSEXT_NAMETYPE_host_name as c_long,
             name as *mut c_void)
}

pub fn ERR_GET_LIB(l: c_ulong) -> c_int {
    ((l >> 24) & 0x0FF) as c_int
}

pub fn ERR_GET_FUNC(l: c_ulong) -> c_int {
    ((l >> 12) & 0xFFF) as c_int
}

pub fn ERR_GET_REASON(l: c_ulong) -> c_int {
    (l & 0xFFF) as c_int
}

extern {
    pub fn ASN1_INTEGER_set(dest: *mut ASN1_INTEGER, value: c_long) -> c_int;
    pub fn ASN1_STRING_type_new(ty: c_int) -> *mut ASN1_STRING;
    pub fn ASN1_TIME_free(tm: *mut ASN1_TIME);
    pub fn ASN1_TIME_print(b: *mut BIO, tm: *const ASN1_TIME) -> c_int;

    pub fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn BIO_free_all(b: *mut BIO);
    pub fn BIO_new_fp(stream: *mut FILE, close_flag: c_int) -> *mut BIO;
    pub fn BIO_new_socket(sock: c_int, close_flag: c_int) -> *mut BIO;
    pub fn BIO_read(b: *mut BIO, buf: *mut c_void, len: c_int) -> c_int;
    pub fn BIO_write(b: *mut BIO, buf: *const c_void, len: c_int) -> c_int;
    #[cfg(ossl101)]
    pub fn BIO_new_mem_buf(buf: *mut c_void, len: c_int) -> *mut BIO;
    #[cfg(not(ossl101))]
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    pub fn BIO_set_flags(b: *mut BIO, flags: c_int);
    pub fn BIO_clear_flags(b: *mut BIO, flags: c_int);

    pub fn BN_new() -> *mut BIGNUM;
    pub fn BN_dup(n: *const BIGNUM) -> *mut BIGNUM;
    pub fn BN_clear(bn: *mut BIGNUM);
    pub fn BN_free(bn: *mut BIGNUM);
    pub fn BN_clear_free(bn: *mut BIGNUM);

    pub fn BN_CTX_new() -> *mut BN_CTX;
    pub fn BN_CTX_free(ctx: *mut BN_CTX);

    pub fn BN_num_bits(bn: *const BIGNUM) -> c_int;
    pub fn BN_set_negative(bn: *mut BIGNUM, n: c_int);
    pub fn BN_set_word(bn: *mut BIGNUM, n: BN_ULONG) -> c_int;

    /* Arithmetic operations on BIGNUMs */
    pub fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    pub fn BN_div(dv: *mut BIGNUM, rem: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_gcd(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_inverse(r: *mut BIGNUM, a: *const BIGNUM, n: *const BIGNUM, ctx: *mut BN_CTX) -> *mut BIGNUM;
    pub fn BN_mod_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_sqr(r: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mod_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_nnmod(rem: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_add_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_sub_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_mul_word(r: *mut BIGNUM, w: BN_ULONG) -> c_int;
    pub fn BN_div_word(r: *mut BIGNUM, w: BN_ULONG) -> BN_ULONG;
    pub fn BN_mod_word(r: *const BIGNUM, w: BN_ULONG) -> BN_ULONG;
    pub fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> c_int;
    pub fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> c_int;

    /* Bit operations on BIGNUMs */
    pub fn BN_clear_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_is_bit_set(a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int;
    pub fn BN_mask_bits(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int;
    pub fn BN_set_bit(a: *mut BIGNUM, n: c_int) -> c_int;
    pub fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int;

    /* Comparisons on BIGNUMs */
    pub fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    pub fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;

    /* Prime handling */
    pub fn BN_generate_prime_ex(r: *mut BIGNUM, bits: c_int, safe: c_int, add: *const BIGNUM, rem: *const BIGNUM, cb: *mut BN_GENCB) -> c_int;
    pub fn BN_is_prime_ex(p: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int;
    pub fn BN_is_prime_fasttest_ex(p: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, do_trial_division: c_int, cb: *mut BN_GENCB) -> c_int;

    /* Random number handling */
    pub fn BN_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    pub fn BN_pseudo_rand(r: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int;
    pub fn BN_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int;
    pub fn BN_pseudo_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int;

    /* Conversion from/to binary representation */
    pub fn BN_bin2bn(s: *const u8, size: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    pub fn BN_bn2bin(a: *const BIGNUM, to: *mut u8) -> c_int;

    /* Conversion from/to decimal string representation */
    pub fn BN_dec2bn(a: *mut *mut BIGNUM, s: *const c_char) -> c_int;
    pub fn BN_bn2dec(a: *const BIGNUM) -> *mut c_char;

    /* Conversion from/to hexidecimal string representation */
    pub fn BN_hex2bn(a: *mut *mut BIGNUM, s: *const c_char) -> c_int;
    pub fn BN_bn2hex(a: *const BIGNUM) -> *mut c_char;

    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void,
                         len: size_t) -> c_int;

    pub fn DH_new() -> *mut DH;
    pub fn DH_free(dh: *mut DH);
    #[cfg(not(ossl101))]
    pub fn DH_get_1024_160() -> *mut DH;
    #[cfg(not(ossl101))]
    pub fn DH_get_2048_224() -> *mut DH;
    #[cfg(not(ossl101))]
    pub fn DH_get_2048_256() -> *mut DH;

    pub fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EC_KEY;
    pub fn EC_KEY_free(key: *mut EC_KEY);

    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_lib_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_func_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_reason_error_string(err: c_ulong) -> *const c_char;

    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_ripemd160() -> *const EVP_MD;
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha224() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_sha512() -> *const EVP_MD;

    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_rc4() -> *const EVP_CIPHER;

    pub fn EVP_des_cbc() -> *const EVP_CIPHER;
    pub fn EVP_des_ecb() -> *const EVP_CIPHER;

    pub fn EVP_BytesToKey(typ: *const EVP_CIPHER, md: *const EVP_MD,
                          salt: *const u8, data: *const u8, datalen: c_int,
                          count: c_int, key: *mut u8, iv: *mut u8) -> c_int;

    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, padding: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_ctrl(ctx: *mut EVP_CIPHER_CTX, type_: c_int, arg: c_int, ptr: *mut c_void) -> c_int;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);

    pub fn EVP_CipherInit(ctx: *mut EVP_CIPHER_CTX, evp: *const EVP_CIPHER,
                          key: *const u8, iv: *const u8, mode: c_int) -> c_int;
    pub fn EVP_CipherInit_ex(ctx: *mut EVP_CIPHER_CTX,
                             type_: *const EVP_CIPHER,
                             impl_: *mut ENGINE,
                             key: *const c_uchar,
                             iv: *const c_uchar,
                             enc: c_int) -> c_int;
    pub fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX, outbuf: *mut u8,
                            outlen: *mut c_int, inbuf: *const u8, inlen: c_int) -> c_int;
    pub fn EVP_CipherFinal(ctx: *mut EVP_CIPHER_CTX, res: *mut u8, len: *mut c_int) -> c_int;

    pub fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD) -> c_int;
    pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD, imple: *mut ENGINE) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, n: size_t) -> c_int;
    pub fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;

    pub fn EVP_DigestSignInit(ctx: *mut EVP_MD_CTX,
                              pctx: *mut *mut EVP_PKEY_CTX,
                              type_: *const EVP_MD,
                              e: *mut ENGINE,
                              pkey: *mut EVP_PKEY) -> c_int;
    pub fn EVP_DigestSignFinal(ctx: *mut EVP_MD_CTX,
                               sig: *mut c_uchar,
                               siglen: *mut size_t) -> c_int;
    pub fn EVP_DigestVerifyInit(ctx: *mut EVP_MD_CTX,
                                pctx: *mut *mut EVP_PKEY_CTX,
                                type_: *const EVP_MD,
                                e: *mut ENGINE,
                                pkey: *mut EVP_PKEY) -> c_int;
    #[cfg(ossl101)]
    pub fn EVP_DigestVerifyFinal(ctx: *mut EVP_MD_CTX,
                                 sigret: *mut c_uchar,
                                 siglen: size_t) -> c_int;
    #[cfg(not(ossl101))]
    pub fn EVP_DigestVerifyFinal(ctx: *mut EVP_MD_CTX,
                                 sigret: *const c_uchar,
                                 siglen: size_t) -> c_int;

    pub fn EVP_MD_CTX_copy_ex(dst: *mut EVP_MD_CTX, src: *const EVP_MD_CTX) -> c_int;

    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    pub fn EVP_PKEY_free(k: *mut EVP_PKEY);
    pub fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, typ: c_int, key: *mut c_void) -> c_int;
    pub fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_get1_RSA(k: *mut EVP_PKEY) -> *mut RSA;
    pub fn EVP_PKEY_set1_RSA(k: *mut EVP_PKEY, r: *mut RSA) -> c_int;
    pub fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_new_mac_key(type_: c_int,
                                e: *mut ENGINE,
                                key: *const c_uchar,
                                keylen: c_int) -> *mut EVP_PKEY;

    pub fn HMAC_CTX_copy(dst: *mut HMAC_CTX, src: *mut HMAC_CTX) -> c_int;

    pub fn PEM_read_bio_DHparams(bio: *mut BIO, out: *mut *mut DH, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut DH;
    pub fn PEM_read_bio_X509(bio: *mut BIO, out: *mut *mut X509, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut X509;
    pub fn PEM_read_bio_X509_REQ(bio: *mut BIO, out: *mut *mut X509_REQ, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut X509_REQ;
    pub fn PEM_read_bio_PrivateKey(bio: *mut BIO, out: *mut *mut EVP_PKEY, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut EVP_PKEY;
    pub fn PEM_read_bio_PUBKEY(bio: *mut BIO, out: *mut *mut EVP_PKEY, callback: Option<PasswordCallback>,
                             user_data: *mut c_void) -> *mut EVP_PKEY;

    pub fn PEM_read_bio_RSAPrivateKey(bio: *mut BIO, rsa: *mut *mut RSA, callback: Option<PasswordCallback>, user_data: *mut c_void) -> *mut RSA;
    pub fn PEM_read_bio_RSA_PUBKEY(bio:    *mut BIO, rsa: *mut *mut RSA, callback: Option<PasswordCallback>, user_data: *mut c_void) -> *mut RSA;

    pub fn PEM_write_bio_DHparams(bio: *mut BIO, x: *const DH) -> c_int;
    pub fn PEM_write_bio_PrivateKey(bio: *mut BIO, pkey: *mut EVP_PKEY, cipher: *const EVP_CIPHER,
                                    kstr: *mut c_uchar, klen: c_int,
                                    callback: Option<PasswordCallback>,
                                    user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_PUBKEY(bp: *mut BIO, x: *mut EVP_PKEY) -> c_int;
    pub fn PEM_write_bio_RSAPrivateKey(bp: *mut BIO, rsa: *mut RSA, cipher: *const EVP_CIPHER,
                                        kstr: *mut c_uchar, klen: c_int,
                                        callback: Option<PasswordCallback>,
                                        user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_RSAPublicKey(bp: *mut BIO, rsa: *const RSA) -> c_int;
    pub fn PEM_write_bio_RSA_PUBKEY(bp: *mut BIO, rsa: *mut RSA) -> c_int;

    pub fn PEM_read_bio_DSAPrivateKey(bp: *mut BIO, dsa: *mut *mut DSA, callback: Option<PasswordCallback>,
                                      user_data: *mut c_void) -> *mut DSA;
    pub fn PEM_read_bio_DSA_PUBKEY(bp: *mut BIO, dsa: *mut *mut DSA, callback: Option<PasswordCallback>,
                                   user_data: *mut c_void) -> *mut DSA;
    pub fn PEM_write_bio_DSAPrivateKey(bp: *mut BIO, dsa: *mut DSA, cipher: *const EVP_CIPHER,
                                       kstr: *mut c_uchar, klen: c_int, callback: Option<PasswordCallback>,
                                       user_data: *mut c_void) -> c_int;
    pub fn PEM_write_bio_DSA_PUBKEY(bp: *mut BIO, dsa: *mut DSA) -> c_int;



    pub fn PEM_write_bio_X509(bio: *mut BIO, x509: *mut X509) -> c_int;
    pub fn PEM_write_bio_X509_REQ(bio: *mut BIO, x509: *mut X509_REQ) -> c_int;

    pub fn PKCS5_PBKDF2_HMAC_SHA1(pass: *const c_char, passlen: c_int,
                                  salt: *const u8, saltlen: c_int,
                                  iter: c_int, keylen: c_int,
                                  out: *mut u8) -> c_int;
    pub fn PKCS5_PBKDF2_HMAC(pass: *const c_char, passlen: c_int,
                             salt: *const c_uchar, saltlen: c_int,
                             iter: c_int, digest: *const EVP_MD, keylen: c_int,
                             out: *mut u8) -> c_int;

    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    pub fn RAND_status() -> c_int;

    pub fn RSA_new() -> *mut RSA;
    pub fn RSA_free(rsa: *mut RSA);
    pub fn RSA_generate_key_ex(rsa: *mut RSA, bits: c_int, e: *mut BIGNUM, cb: *mut BN_GENCB) -> c_int;
    pub fn RSA_private_decrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                               pad: c_int) -> c_int;
    pub fn RSA_public_decrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                               pad: c_int) -> c_int;
    pub fn RSA_private_encrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                              pad: c_int) -> c_int;
    pub fn RSA_public_encrypt(flen: c_int, from: *const u8, to: *mut u8, k: *mut RSA,
                              pad: c_int) -> c_int;
    pub fn RSA_sign(t: c_int, m: *const u8, mlen: c_uint, sig: *mut u8, siglen: *mut c_uint,
                    k: *mut RSA) -> c_int;
    pub fn RSA_size(k: *const RSA) -> c_int;
    pub fn RSA_verify(t: c_int, m: *const u8, mlen: c_uint, sig: *const u8, siglen: c_uint,
                      k: *mut RSA) -> c_int;

    pub fn DSA_new() -> *mut DSA;
    pub fn DSA_free(dsa: *mut DSA);
    pub fn DSA_size(dsa: *const DSA) -> c_int;
    pub fn DSA_generate_parameters_ex(dsa: *mut DSA, bits: c_int, seed: *const c_uchar, seed_len: c_int,
                                      counter_ref: *mut c_int, h_ret: *mut c_ulong,
                                      cb: *mut BN_GENCB) -> c_int;
    pub fn DSA_generate_key(dsa: *mut DSA) -> c_int;
    pub fn DSA_sign(dummy: c_int, dgst: *const c_uchar, len: c_int, sigret: *mut c_uchar,
                    siglen: *mut c_uint, dsa: *mut DSA) -> c_int;
    pub fn DSA_verify(dummy: c_int, dgst: *const c_uchar, len: c_int, sigbuf: *const c_uchar,
                      siglen: c_int, dsa: *mut DSA) -> c_int;

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    pub fn SSL_pending(ssl: *const SSL) -> c_int;
    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub fn SSL_get_rbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_wbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_accept(ssl: *mut SSL) -> c_int;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    pub fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long,
                    parg: *mut c_void) -> c_long;
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;
    pub fn SSL_set_SSL_CTX(ssl: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX;
    #[cfg(not(osslconf = "OPENSSL_NO_COMP"))]
    pub fn SSL_get_current_compression(ssl: *mut SSL) -> *const COMP_METHOD;
    pub fn SSL_get_peer_certificate(ssl: *const SSL) -> *mut X509;
    pub fn SSL_get_ssl_method(ssl: *mut SSL) -> *const SSL_METHOD;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string_long(ssl: *const SSL) -> *const c_char;
    pub fn SSL_set_verify(ssl: *mut SSL,
                          mode: c_int,
                          verify_callback: Option<extern fn(c_int, *mut X509_STORE_CTX) -> c_int>);
    pub fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;
    pub fn SSL_get_servername(ssl: *const SSL, name_type: c_int) -> *const c_char;
    pub fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;
    #[cfg(not(ossl101))]
    pub fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;
    pub fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;
    pub fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
    #[cfg(ossl101)]
    pub fn SSL_get_privatekey(ssl: *mut SSL) -> *mut EVP_PKEY;
    #[cfg(not(ossl101))]
    pub fn SSL_get_privatekey(ssl: *const SSL) -> *mut EVP_PKEY;
    pub fn SSL_load_client_CA_file(file: *const c_char) -> *mut stack_st_X509_NAME;

    #[cfg(not(osslconf = "OPENSSL_NO_COMP"))]
    pub fn SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char;

    pub fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char;
    pub fn SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int;
    pub fn SSL_CIPHER_description(cipher: *const SSL_CIPHER, buf: *mut c_char, size: c_int) -> *mut c_char;

    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_callback_ctrl(ctx: *mut SSL_CTX, cmd: c_int, fp: Option<extern "C" fn()>) -> c_long;
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int,
                              verify_callback: Option<extern fn(c_int, *mut X509_STORE_CTX) -> c_int>);
    pub fn SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int);
    pub fn SSL_CTX_load_verify_locations(ctx: *mut SSL_CTX, CAfile: *const c_char,
                                         CApath: *const c_char) -> c_int;
    pub fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void)
                               -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void;
    pub fn SSL_CTX_set_session_id_context(ssl: *mut SSL_CTX, sid_ctx: *const c_uchar, sid_ctx_len: c_uint) -> c_int;

    pub fn SSL_CTX_use_certificate_file(ctx: *mut SSL_CTX, cert_file: *const c_char, file_type: c_int) -> c_int;
    pub fn SSL_CTX_use_certificate_chain_file(ctx: *mut SSL_CTX, cert_chain_file: *const c_char) -> c_int;
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, cert: *mut X509) -> c_int;

    pub fn SSL_CTX_use_PrivateKey_file(ctx: *mut SSL_CTX, key_file: *const c_char, file_type: c_int) -> c_int;
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, key: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_CTX_set_client_CA_list(ctx: *mut SSL_CTX, list: *mut stack_st_X509_NAME);

    #[cfg(not(ossl101))]
    pub fn SSL_CTX_get0_certificate(ctx: *const SSL_CTX) -> *mut X509;
    #[cfg(not(ossl101))]
    pub fn SSL_CTX_get0_privatekey(ctx: *const SSL_CTX) -> *mut EVP_PKEY;

    pub fn SSL_CTX_set_cipher_list(ssl: *mut SSL_CTX, s: *const c_char) -> c_int;

    pub fn SSL_CTX_set_next_protos_advertised_cb(ssl: *mut SSL_CTX,
                                                 cb: extern "C" fn(ssl: *mut SSL,
                                                                   out: *mut *const c_uchar,
                                                                   outlen: *mut c_uint,
                                                                   arg: *mut c_void) -> c_int,
                                                 arg: *mut c_void);
    pub fn SSL_CTX_set_next_proto_select_cb(ssl: *mut SSL_CTX,
                                            cb: extern "C" fn(ssl: *mut SSL,
                                                              out: *mut *mut c_uchar,
                                                              outlen: *mut c_uchar,
                                                              inbuf: *const c_uchar,
                                                              inlen: c_uint,
                                                              arg: *mut c_void) -> c_int,
                                            arg: *mut c_void);
    pub fn SSL_select_next_proto(out: *mut *mut c_uchar, outlen: *mut c_uchar,
                                 inbuf: *const c_uchar, inlen: c_uint,
                                 client: *const c_uchar, client_len: c_uint) -> c_int;
    pub fn SSL_get0_next_proto_negotiated(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);

    #[cfg(not(ossl101))]
    pub fn SSL_CTX_set_alpn_protos(s: *mut SSL_CTX, data: *const c_uchar, len: c_uint) -> c_int;

    #[cfg(not(ossl101))]
    pub fn SSL_set_alpn_protos(s: *mut SSL, data: *const c_uchar, len: c_uint) -> c_int;

    #[cfg(not(ossl101))]
    pub fn SSL_CTX_set_alpn_select_cb(ssl: *mut SSL_CTX,
                                      cb: extern fn(ssl: *mut SSL,
                                                    out: *mut *const c_uchar,
                                                    outlen: *mut c_uchar,
                                                    inbuf: *const c_uchar,
                                                    inlen: c_uint,
                                                    arg: *mut c_void) -> c_int,
                                      arg: *mut c_void);
    #[cfg(not(ossl101))]
    pub fn SSL_get0_alpn_selected(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);

    pub fn X509_add_ext(x: *mut X509, ext: *mut X509_EXTENSION, loc: c_int) -> c_int;
    pub fn X509_digest(x: *const X509, digest: *const EVP_MD, buf: *mut c_uchar, len: *mut c_uint) -> c_int;
    pub fn X509_free(x: *mut X509);
    pub fn X509_REQ_free(x: *mut X509_REQ);
    pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
    pub fn X509_gmtime_adj(time: *mut ASN1_TIME, adj: c_long) -> *mut ASN1_TIME;
    pub fn X509_new() -> *mut X509;
    pub fn X509_set_issuer_name(x: *mut X509, name: *mut X509_NAME) -> c_int;
    pub fn X509_set_version(x: *mut X509, version: c_long) -> c_int;
    pub fn X509_set_pubkey(x: *mut X509, pkey: *mut EVP_PKEY) -> c_int;
    pub fn X509_sign(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;
    pub fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;
    pub fn X509_to_X509_REQ(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> *mut X509_REQ;
    pub fn X509_verify_cert_error_string(n: c_long) -> *const c_char;

    pub fn X509_EXTENSION_free(ext: *mut X509_EXTENSION);

    pub fn X509_NAME_free(x: *mut X509_NAME);
    pub fn X509_NAME_add_entry_by_txt(x: *mut X509_NAME, field: *const c_char, ty: c_int, bytes: *const c_uchar, len: c_int, loc: c_int, set: c_int) -> c_int;
    pub fn X509_NAME_get_index_by_NID(n: *mut X509_NAME, nid: c_int, last_pos: c_int) -> c_int;

    pub fn X509_NAME_ENTRY_free(x: *mut X509_NAME_ENTRY);

    pub fn ASN1_STRING_free(x: *mut ASN1_STRING);
    pub fn ASN1_STRING_length(x: *const ASN1_STRING) -> c_int;

    pub fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);
    pub fn X509_STORE_CTX_get_current_cert(ctx: *mut X509_STORE_CTX) -> *mut X509;
    pub fn X509_STORE_CTX_get_error(ctx: *mut X509_STORE_CTX) -> c_int;
    pub fn X509_STORE_CTX_get_ex_data(ctx: *mut X509_STORE_CTX, idx: c_int) -> *mut c_void;
    pub fn X509_STORE_CTX_get_error_depth(ctx: *mut X509_STORE_CTX) -> c_int;

    pub fn X509V3_set_ctx(ctx: *mut X509V3_CTX, issuer: *mut X509, subject: *mut X509, req: *mut X509_REQ, crl: *mut X509_CRL, flags: c_int);

    pub fn X509_REQ_add_extensions(req: *mut X509_REQ, exts: *mut stack_st_X509_EXTENSION) -> c_int;
    pub fn X509_REQ_sign(x: *mut X509_REQ, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

    #[cfg(not(ossl101))]
    pub fn X509_VERIFY_PARAM_free(param: *mut X509_VERIFY_PARAM);
    #[cfg(not(ossl101))]
    pub fn X509_VERIFY_PARAM_set_hostflags(param: *mut X509_VERIFY_PARAM, flags: c_uint);
    #[cfg(not(ossl101))]
    pub fn X509_VERIFY_PARAM_set1_host(param: *mut X509_VERIFY_PARAM,
                                       name: *const c_char,
                                       namelen: size_t) -> c_int;

    pub fn d2i_X509(a: *mut *mut X509, pp: *mut *const c_uchar, length: c_long) -> *mut X509;
    pub fn i2d_X509_bio(b: *mut BIO, x: *mut X509) -> c_int;
    pub fn i2d_X509_REQ_bio(b: *mut BIO, x: *mut X509_REQ) -> c_int;

    pub fn i2d_PUBKEY_bio(b: *mut BIO, x: *mut EVP_PKEY) -> c_int;

    pub fn i2d_RSA_PUBKEY(k: *mut RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSA_PUBKEY(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;
    pub fn i2d_RSAPrivateKey(k: *const RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSAPrivateKey(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;

    pub fn d2i_PKCS12(a: *mut *mut PKCS12, pp: *mut *const u8, length: c_long) -> *mut PKCS12;
    pub fn PKCS12_parse(p12: *mut PKCS12,
                        pass: *const c_char,
                        pkey: *mut *mut EVP_PKEY,
                        cert: *mut *mut X509,
                        ca: *mut *mut stack_st_X509)
                        -> c_int;
    pub fn PKCS12_free(p12: *mut PKCS12);

    pub fn GENERAL_NAME_free(name: *mut GENERAL_NAME);

    pub fn HMAC_Init_ex(ctx: *mut HMAC_CTX,
                        key: *const c_void,
                        len: c_int,
                        md: *const EVP_MD,
                        impl_: *mut ENGINE) -> c_int;
    pub fn HMAC_Update(ctx: *mut HMAC_CTX,
                       data: *const c_uchar,
                       len: size_t) -> c_int;
    pub fn HMAC_Final(ctx: *mut HMAC_CTX,
                      md: *mut c_uchar,
                      len: *mut c_uint) -> c_int;
}
