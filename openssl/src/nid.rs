use ffi;
use libc::c_int;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Nid(c_int);

#[allow(non_snake_case)]
impl Nid {
    pub fn from_raw(raw: c_int) -> Nid {
        Nid(raw)
    }

    pub fn as_raw(&self) -> c_int {
        self.0
    }

    pub fn undef() -> Nid {
        Nid(ffi::NID_undef)
    }

    pub fn itu_t() -> Nid {
        Nid(ffi::NID_itu_t)
    }

    pub fn ccitt() -> Nid {
        Nid(ffi::NID_ccitt)
    }

    pub fn iso() -> Nid {
        Nid(ffi::NID_iso)
    }

    pub fn joint_iso_itu_t() -> Nid {
        Nid(ffi::NID_joint_iso_itu_t)
    }

    pub fn joint_iso_ccitt() -> Nid {
        Nid(ffi::NID_joint_iso_ccitt)
    }

    pub fn member_body() -> Nid {
        Nid(ffi::NID_member_body)
    }

    pub fn identified_organization() -> Nid {
        Nid(ffi::NID_identified_organization)
    }

    pub fn hmac_md5() -> Nid {
        Nid(ffi::NID_hmac_md5)
    }

    pub fn hmac_sha1() -> Nid {
        Nid(ffi::NID_hmac_sha1)
    }

    pub fn certicom_arc() -> Nid {
        Nid(ffi::NID_certicom_arc)
    }

    pub fn international_organizations() -> Nid {
        Nid(ffi::NID_international_organizations)
    }

    pub fn wap() -> Nid {
        Nid(ffi::NID_wap)
    }

    pub fn wap_wsg() -> Nid {
        Nid(ffi::NID_wap_wsg)
    }

    pub fn selected_attribute_types() -> Nid {
        Nid(ffi::NID_selected_attribute_types)
    }

    pub fn clearance() -> Nid {
        Nid(ffi::NID_clearance)
    }

    pub fn ISO_US() -> Nid {
        Nid(ffi::NID_ISO_US)
    }

    pub fn X9_57() -> Nid {
        Nid(ffi::NID_X9_57)
    }

    pub fn X9cm() -> Nid {
        Nid(ffi::NID_X9cm)
    }

    pub fn dsa() -> Nid {
        Nid(ffi::NID_dsa)
    }

    pub fn dsaWithSHA1() -> Nid {
        Nid(ffi::NID_dsaWithSHA1)
    }

    pub fn ansi_X9_62() -> Nid {
        Nid(ffi::NID_ansi_X9_62)
    }

    pub fn X9_62_prime_field() -> Nid {
        Nid(ffi::NID_X9_62_prime_field)
    }

    pub fn X9_62_characteristic_two_field() -> Nid {
        Nid(ffi::NID_X9_62_characteristic_two_field)
    }

    pub fn X9_62_id_characteristic_two_basis() -> Nid {
        Nid(ffi::NID_X9_62_id_characteristic_two_basis)
    }

    pub fn X9_62_onBasis() -> Nid {
        Nid(ffi::NID_X9_62_onBasis)
    }

    pub fn X9_62_tpBasis() -> Nid {
        Nid(ffi::NID_X9_62_tpBasis)
    }

    pub fn X9_62_ppBasis() -> Nid {
        Nid(ffi::NID_X9_62_ppBasis)
    }

    pub fn X9_62_id_ecPublicKey() -> Nid {
        Nid(ffi::NID_X9_62_id_ecPublicKey)
    }

    pub fn X9_62_c2pnb163v1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb163v1)
    }

    pub fn X9_62_c2pnb163v2() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb163v2)
    }

    pub fn X9_62_c2pnb163v3() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb163v3)
    }

    pub fn X9_62_c2pnb176v1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb176v1)
    }

    pub fn X9_62_c2tnb191v1() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb191v1)
    }

    pub fn X9_62_c2tnb191v2() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb191v2)
    }

    pub fn X9_62_c2tnb191v3() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb191v3)
    }

    pub fn X9_62_c2onb191v4() -> Nid {
        Nid(ffi::NID_X9_62_c2onb191v4)
    }

    pub fn X9_62_c2onb191v5() -> Nid {
        Nid(ffi::NID_X9_62_c2onb191v5)
    }

    pub fn X9_62_c2pnb208w1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb208w1)
    }

    pub fn X9_62_c2tnb239v1() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb239v1)
    }

    pub fn X9_62_c2tnb239v2() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb239v2)
    }

    pub fn X9_62_c2tnb239v3() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb239v3)
    }

    pub fn X9_62_c2onb239v4() -> Nid {
        Nid(ffi::NID_X9_62_c2onb239v4)
    }

    pub fn X9_62_c2onb239v5() -> Nid {
        Nid(ffi::NID_X9_62_c2onb239v5)
    }

    pub fn X9_62_c2pnb272w1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb272w1)
    }

    pub fn X9_62_c2pnb304w1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb304w1)
    }

    pub fn X9_62_c2tnb359v1() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb359v1)
    }

    pub fn X9_62_c2pnb368w1() -> Nid {
        Nid(ffi::NID_X9_62_c2pnb368w1)
    }

    pub fn X9_62_c2tnb431r1() -> Nid {
        Nid(ffi::NID_X9_62_c2tnb431r1)
    }

    pub fn X9_62_prime192v1() -> Nid {
        Nid(ffi::NID_X9_62_prime192v1)
    }

    pub fn X9_62_prime192v2() -> Nid {
        Nid(ffi::NID_X9_62_prime192v2)
    }

    pub fn X9_62_prime192v3() -> Nid {
        Nid(ffi::NID_X9_62_prime192v3)
    }

    pub fn X9_62_prime239v1() -> Nid {
        Nid(ffi::NID_X9_62_prime239v1)
    }

    pub fn X9_62_prime239v2() -> Nid {
        Nid(ffi::NID_X9_62_prime239v2)
    }

    pub fn X9_62_prime239v3() -> Nid {
        Nid(ffi::NID_X9_62_prime239v3)
    }

    pub fn X9_62_prime256v1() -> Nid {
        Nid(ffi::NID_X9_62_prime256v1)
    }

    pub fn ecdsa_with_SHA1() -> Nid {
        Nid(ffi::NID_ecdsa_with_SHA1)
    }

    pub fn ecdsa_with_Recommended() -> Nid {
        Nid(ffi::NID_ecdsa_with_Recommended)
    }

    pub fn ecdsa_with_Specified() -> Nid {
        Nid(ffi::NID_ecdsa_with_Specified)
    }

    pub fn ecdsa_with_SHA224() -> Nid {
        Nid(ffi::NID_ecdsa_with_SHA224)
    }

    pub fn ecdsa_with_SHA256() -> Nid {
        Nid(ffi::NID_ecdsa_with_SHA256)
    }

    pub fn ecdsa_with_SHA384() -> Nid {
        Nid(ffi::NID_ecdsa_with_SHA384)
    }

    pub fn ecdsa_with_SHA512() -> Nid {
        Nid(ffi::NID_ecdsa_with_SHA512)
    }

    pub fn secp112r1() -> Nid {
        Nid(ffi::NID_secp112r1)
    }

    pub fn secp112r2() -> Nid {
        Nid(ffi::NID_secp112r2)
    }

    pub fn secp128r1() -> Nid {
        Nid(ffi::NID_secp128r1)
    }

    pub fn secp128r2() -> Nid {
        Nid(ffi::NID_secp128r2)
    }

    pub fn secp160k1() -> Nid {
        Nid(ffi::NID_secp160k1)
    }

    pub fn secp160r1() -> Nid {
        Nid(ffi::NID_secp160r1)
    }

    pub fn secp160r2() -> Nid {
        Nid(ffi::NID_secp160r2)
    }

    pub fn secp192k1() -> Nid {
        Nid(ffi::NID_secp192k1)
    }

    pub fn secp224k1() -> Nid {
        Nid(ffi::NID_secp224k1)
    }

    pub fn secp224r1() -> Nid {
        Nid(ffi::NID_secp224r1)
    }

    pub fn secp256k1() -> Nid {
        Nid(ffi::NID_secp256k1)
    }

    pub fn secp384r1() -> Nid {
        Nid(ffi::NID_secp384r1)
    }

    pub fn secp521r1() -> Nid {
        Nid(ffi::NID_secp521r1)
    }

    pub fn sect113r1() -> Nid {
        Nid(ffi::NID_sect113r1)
    }

    pub fn sect113r2() -> Nid {
        Nid(ffi::NID_sect113r2)
    }

    pub fn sect131r1() -> Nid {
        Nid(ffi::NID_sect131r1)
    }

    pub fn sect131r2() -> Nid {
        Nid(ffi::NID_sect131r2)
    }

    pub fn sect163k1() -> Nid {
        Nid(ffi::NID_sect163k1)
    }

    pub fn sect163r1() -> Nid {
        Nid(ffi::NID_sect163r1)
    }

    pub fn sect163r2() -> Nid {
        Nid(ffi::NID_sect163r2)
    }

    pub fn sect193r1() -> Nid {
        Nid(ffi::NID_sect193r1)
    }

    pub fn sect193r2() -> Nid {
        Nid(ffi::NID_sect193r2)
    }

    pub fn sect233k1() -> Nid {
        Nid(ffi::NID_sect233k1)
    }

    pub fn sect233r1() -> Nid {
        Nid(ffi::NID_sect233r1)
    }

    pub fn sect239k1() -> Nid {
        Nid(ffi::NID_sect239k1)
    }

    pub fn sect283k1() -> Nid {
        Nid(ffi::NID_sect283k1)
    }

    pub fn sect283r1() -> Nid {
        Nid(ffi::NID_sect283r1)
    }

    pub fn sect409k1() -> Nid {
        Nid(ffi::NID_sect409k1)
    }

    pub fn sect409r1() -> Nid {
        Nid(ffi::NID_sect409r1)
    }

    pub fn sect571k1() -> Nid {
        Nid(ffi::NID_sect571k1)
    }

    pub fn sect571r1() -> Nid {
        Nid(ffi::NID_sect571r1)
    }

    pub fn wap_wsg_idm_ecid_wtls1() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls1)
    }

    pub fn wap_wsg_idm_ecid_wtls3() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls3)
    }

    pub fn wap_wsg_idm_ecid_wtls4() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls4)
    }

    pub fn wap_wsg_idm_ecid_wtls5() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls5)
    }

    pub fn wap_wsg_idm_ecid_wtls6() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls6)
    }

    pub fn wap_wsg_idm_ecid_wtls7() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls7)
    }

    pub fn wap_wsg_idm_ecid_wtls8() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls8)
    }

    pub fn wap_wsg_idm_ecid_wtls9() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls9)
    }

    pub fn wap_wsg_idm_ecid_wtls10() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls10)
    }

    pub fn wap_wsg_idm_ecid_wtls11() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls11)
    }

    pub fn wap_wsg_idm_ecid_wtls12() -> Nid {
        Nid(ffi::NID_wap_wsg_idm_ecid_wtls12)
    }

    pub fn cast5_cbc() -> Nid {
        Nid(ffi::NID_cast5_cbc)
    }

    pub fn cast5_ecb() -> Nid {
        Nid(ffi::NID_cast5_ecb)
    }

    pub fn cast5_cfb64() -> Nid {
        Nid(ffi::NID_cast5_cfb64)
    }

    pub fn cast5_ofb64() -> Nid {
        Nid(ffi::NID_cast5_ofb64)
    }

    pub fn pbeWithMD5AndCast5_CBC() -> Nid {
        Nid(ffi::NID_pbeWithMD5AndCast5_CBC)
    }

    pub fn id_PasswordBasedMAC() -> Nid {
        Nid(ffi::NID_id_PasswordBasedMAC)
    }

    pub fn id_DHBasedMac() -> Nid {
        Nid(ffi::NID_id_DHBasedMac)
    }

    pub fn rsadsi() -> Nid {
        Nid(ffi::NID_rsadsi)
    }

    pub fn pkcs() -> Nid {
        Nid(ffi::NID_pkcs)
    }

    pub fn pkcs1() -> Nid {
        Nid(ffi::NID_pkcs1)
    }

    pub fn rsaEncryption() -> Nid {
        Nid(ffi::NID_rsaEncryption)
    }

    pub fn md2WithRSAEncryption() -> Nid {
        Nid(ffi::NID_md2WithRSAEncryption)
    }

    pub fn md4WithRSAEncryption() -> Nid {
        Nid(ffi::NID_md4WithRSAEncryption)
    }

    pub fn md5WithRSAEncryption() -> Nid {
        Nid(ffi::NID_md5WithRSAEncryption)
    }

    pub fn sha1WithRSAEncryption() -> Nid {
        Nid(ffi::NID_sha1WithRSAEncryption)
    }

    pub fn rsaesOaep() -> Nid {
        Nid(ffi::NID_rsaesOaep)
    }

    pub fn mgf1() -> Nid {
        Nid(ffi::NID_mgf1)
    }

    pub fn pSpecified() -> Nid {
        Nid(ffi::NID_pSpecified)
    }

    pub fn rsassaPss() -> Nid {
        Nid(ffi::NID_rsassaPss)
    }

    pub fn sha256WithRSAEncryption() -> Nid {
        Nid(ffi::NID_sha256WithRSAEncryption)
    }

    pub fn sha384WithRSAEncryption() -> Nid {
        Nid(ffi::NID_sha384WithRSAEncryption)
    }

    pub fn sha512WithRSAEncryption() -> Nid {
        Nid(ffi::NID_sha512WithRSAEncryption)
    }

    pub fn sha224WithRSAEncryption() -> Nid {
        Nid(ffi::NID_sha224WithRSAEncryption)
    }

    pub fn pkcs3() -> Nid {
        Nid(ffi::NID_pkcs3)
    }

    pub fn dhKeyAgreement() -> Nid {
        Nid(ffi::NID_dhKeyAgreement)
    }

    pub fn pkcs5() -> Nid {
        Nid(ffi::NID_pkcs5)
    }

    pub fn pbeWithMD2AndDES_CBC() -> Nid {
        Nid(ffi::NID_pbeWithMD2AndDES_CBC)
    }

    pub fn pbeWithMD5AndDES_CBC() -> Nid {
        Nid(ffi::NID_pbeWithMD5AndDES_CBC)
    }

    pub fn pbeWithMD2AndRC2_CBC() -> Nid {
        Nid(ffi::NID_pbeWithMD2AndRC2_CBC)
    }

    pub fn pbeWithMD5AndRC2_CBC() -> Nid {
        Nid(ffi::NID_pbeWithMD5AndRC2_CBC)
    }

    pub fn pbeWithSHA1AndDES_CBC() -> Nid {
        Nid(ffi::NID_pbeWithSHA1AndDES_CBC)
    }

    pub fn pbeWithSHA1AndRC2_CBC() -> Nid {
        Nid(ffi::NID_pbeWithSHA1AndRC2_CBC)
    }

    pub fn id_pbkdf2() -> Nid {
        Nid(ffi::NID_id_pbkdf2)
    }

    pub fn pbes2() -> Nid {
        Nid(ffi::NID_pbes2)
    }

    pub fn pbmac1() -> Nid {
        Nid(ffi::NID_pbmac1)
    }

    pub fn pkcs7() -> Nid {
        Nid(ffi::NID_pkcs7)
    }

    pub fn pkcs7_data() -> Nid {
        Nid(ffi::NID_pkcs7_data)
    }

    pub fn pkcs7_signed() -> Nid {
        Nid(ffi::NID_pkcs7_signed)
    }

    pub fn pkcs7_enveloped() -> Nid {
        Nid(ffi::NID_pkcs7_enveloped)
    }

    pub fn pkcs7_signedAndEnveloped() -> Nid {
        Nid(ffi::NID_pkcs7_signedAndEnveloped)
    }

    pub fn pkcs7_digest() -> Nid {
        Nid(ffi::NID_pkcs7_digest)
    }

    pub fn pkcs7_encrypted() -> Nid {
        Nid(ffi::NID_pkcs7_encrypted)
    }

    pub fn pkcs9() -> Nid {
        Nid(ffi::NID_pkcs9)
    }

    pub fn pkcs9_emailAddress() -> Nid {
        Nid(ffi::NID_pkcs9_emailAddress)
    }

    pub fn pkcs9_unstructuredName() -> Nid {
        Nid(ffi::NID_pkcs9_unstructuredName)
    }

    pub fn pkcs9_contentType() -> Nid {
        Nid(ffi::NID_pkcs9_contentType)
    }

    pub fn pkcs9_messageDigest() -> Nid {
        Nid(ffi::NID_pkcs9_messageDigest)
    }

    pub fn pkcs9_signingTime() -> Nid {
        Nid(ffi::NID_pkcs9_signingTime)
    }

    pub fn pkcs9_countersignature() -> Nid {
        Nid(ffi::NID_pkcs9_countersignature)
    }

    pub fn pkcs9_challengePassword() -> Nid {
        Nid(ffi::NID_pkcs9_challengePassword)
    }

    pub fn pkcs9_unstructuredAddress() -> Nid {
        Nid(ffi::NID_pkcs9_unstructuredAddress)
    }

    pub fn pkcs9_extCertAttributes() -> Nid {
        Nid(ffi::NID_pkcs9_extCertAttributes)
    }

    pub fn ext_req() -> Nid {
        Nid(ffi::NID_ext_req)
    }

    pub fn SMIMECapabilities() -> Nid {
        Nid(ffi::NID_SMIMECapabilities)
    }

    pub fn SMIME() -> Nid {
        Nid(ffi::NID_SMIME)
    }

    pub fn id_smime_mod() -> Nid {
        Nid(ffi::NID_id_smime_mod)
    }

    pub fn id_smime_ct() -> Nid {
        Nid(ffi::NID_id_smime_ct)
    }

    pub fn id_smime_aa() -> Nid {
        Nid(ffi::NID_id_smime_aa)
    }

    pub fn id_smime_alg() -> Nid {
        Nid(ffi::NID_id_smime_alg)
    }

    pub fn id_smime_cd() -> Nid {
        Nid(ffi::NID_id_smime_cd)
    }

    pub fn id_smime_spq() -> Nid {
        Nid(ffi::NID_id_smime_spq)
    }

    pub fn id_smime_cti() -> Nid {
        Nid(ffi::NID_id_smime_cti)
    }

    pub fn id_smime_mod_cms() -> Nid {
        Nid(ffi::NID_id_smime_mod_cms)
    }

    pub fn id_smime_mod_ess() -> Nid {
        Nid(ffi::NID_id_smime_mod_ess)
    }

    pub fn id_smime_mod_oid() -> Nid {
        Nid(ffi::NID_id_smime_mod_oid)
    }

    pub fn id_smime_mod_msg_v3() -> Nid {
        Nid(ffi::NID_id_smime_mod_msg_v3)
    }

    pub fn id_smime_mod_ets_eSignature_88() -> Nid {
        Nid(ffi::NID_id_smime_mod_ets_eSignature_88)
    }

    pub fn id_smime_mod_ets_eSignature_97() -> Nid {
        Nid(ffi::NID_id_smime_mod_ets_eSignature_97)
    }

    pub fn id_smime_mod_ets_eSigPolicy_88() -> Nid {
        Nid(ffi::NID_id_smime_mod_ets_eSigPolicy_88)
    }

    pub fn id_smime_mod_ets_eSigPolicy_97() -> Nid {
        Nid(ffi::NID_id_smime_mod_ets_eSigPolicy_97)
    }

    pub fn id_smime_ct_receipt() -> Nid {
        Nid(ffi::NID_id_smime_ct_receipt)
    }

    pub fn id_smime_ct_authData() -> Nid {
        Nid(ffi::NID_id_smime_ct_authData)
    }

    pub fn id_smime_ct_publishCert() -> Nid {
        Nid(ffi::NID_id_smime_ct_publishCert)
    }

    pub fn id_smime_ct_TSTInfo() -> Nid {
        Nid(ffi::NID_id_smime_ct_TSTInfo)
    }

    pub fn id_smime_ct_TDTInfo() -> Nid {
        Nid(ffi::NID_id_smime_ct_TDTInfo)
    }

    pub fn id_smime_ct_contentInfo() -> Nid {
        Nid(ffi::NID_id_smime_ct_contentInfo)
    }

    pub fn id_smime_ct_DVCSRequestData() -> Nid {
        Nid(ffi::NID_id_smime_ct_DVCSRequestData)
    }

    pub fn id_smime_ct_DVCSResponseData() -> Nid {
        Nid(ffi::NID_id_smime_ct_DVCSResponseData)
    }

    pub fn id_smime_ct_compressedData() -> Nid {
        Nid(ffi::NID_id_smime_ct_compressedData)
    }

    pub fn id_ct_asciiTextWithCRLF() -> Nid {
        Nid(ffi::NID_id_ct_asciiTextWithCRLF)
    }

    pub fn id_smime_aa_receiptRequest() -> Nid {
        Nid(ffi::NID_id_smime_aa_receiptRequest)
    }

    pub fn id_smime_aa_securityLabel() -> Nid {
        Nid(ffi::NID_id_smime_aa_securityLabel)
    }

    pub fn id_smime_aa_mlExpandHistory() -> Nid {
        Nid(ffi::NID_id_smime_aa_mlExpandHistory)
    }

    pub fn id_smime_aa_contentHint() -> Nid {
        Nid(ffi::NID_id_smime_aa_contentHint)
    }

    pub fn id_smime_aa_msgSigDigest() -> Nid {
        Nid(ffi::NID_id_smime_aa_msgSigDigest)
    }

    pub fn id_smime_aa_encapContentType() -> Nid {
        Nid(ffi::NID_id_smime_aa_encapContentType)
    }

    pub fn id_smime_aa_contentIdentifier() -> Nid {
        Nid(ffi::NID_id_smime_aa_contentIdentifier)
    }

    pub fn id_smime_aa_macValue() -> Nid {
        Nid(ffi::NID_id_smime_aa_macValue)
    }

    pub fn id_smime_aa_equivalentLabels() -> Nid {
        Nid(ffi::NID_id_smime_aa_equivalentLabels)
    }

    pub fn id_smime_aa_contentReference() -> Nid {
        Nid(ffi::NID_id_smime_aa_contentReference)
    }

    pub fn id_smime_aa_encrypKeyPref() -> Nid {
        Nid(ffi::NID_id_smime_aa_encrypKeyPref)
    }

    pub fn id_smime_aa_signingCertificate() -> Nid {
        Nid(ffi::NID_id_smime_aa_signingCertificate)
    }

    pub fn id_smime_aa_smimeEncryptCerts() -> Nid {
        Nid(ffi::NID_id_smime_aa_smimeEncryptCerts)
    }

    pub fn id_smime_aa_timeStampToken() -> Nid {
        Nid(ffi::NID_id_smime_aa_timeStampToken)
    }

    pub fn id_smime_aa_ets_sigPolicyId() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_sigPolicyId)
    }

    pub fn id_smime_aa_ets_commitmentType() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_commitmentType)
    }

    pub fn id_smime_aa_ets_signerLocation() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_signerLocation)
    }

    pub fn id_smime_aa_ets_signerAttr() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_signerAttr)
    }

    pub fn id_smime_aa_ets_otherSigCert() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_otherSigCert)
    }

    pub fn id_smime_aa_ets_contentTimestamp() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_contentTimestamp)
    }

    pub fn id_smime_aa_ets_CertificateRefs() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_CertificateRefs)
    }

    pub fn id_smime_aa_ets_RevocationRefs() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_RevocationRefs)
    }

    pub fn id_smime_aa_ets_certValues() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_certValues)
    }

    pub fn id_smime_aa_ets_revocationValues() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_revocationValues)
    }

    pub fn id_smime_aa_ets_escTimeStamp() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_escTimeStamp)
    }

    pub fn id_smime_aa_ets_certCRLTimestamp() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_certCRLTimestamp)
    }

    pub fn id_smime_aa_ets_archiveTimeStamp() -> Nid {
        Nid(ffi::NID_id_smime_aa_ets_archiveTimeStamp)
    }

    pub fn id_smime_aa_signatureType() -> Nid {
        Nid(ffi::NID_id_smime_aa_signatureType)
    }

    pub fn id_smime_aa_dvcs_dvc() -> Nid {
        Nid(ffi::NID_id_smime_aa_dvcs_dvc)
    }

    pub fn id_smime_alg_ESDHwith3DES() -> Nid {
        Nid(ffi::NID_id_smime_alg_ESDHwith3DES)
    }

    pub fn id_smime_alg_ESDHwithRC2() -> Nid {
        Nid(ffi::NID_id_smime_alg_ESDHwithRC2)
    }

    pub fn id_smime_alg_3DESwrap() -> Nid {
        Nid(ffi::NID_id_smime_alg_3DESwrap)
    }

    pub fn id_smime_alg_RC2wrap() -> Nid {
        Nid(ffi::NID_id_smime_alg_RC2wrap)
    }

    pub fn id_smime_alg_ESDH() -> Nid {
        Nid(ffi::NID_id_smime_alg_ESDH)
    }

    pub fn id_smime_alg_CMS3DESwrap() -> Nid {
        Nid(ffi::NID_id_smime_alg_CMS3DESwrap)
    }

    pub fn id_smime_alg_CMSRC2wrap() -> Nid {
        Nid(ffi::NID_id_smime_alg_CMSRC2wrap)
    }

    pub fn id_alg_PWRI_KEK() -> Nid {
        Nid(ffi::NID_id_alg_PWRI_KEK)
    }

    pub fn id_smime_cd_ldap() -> Nid {
        Nid(ffi::NID_id_smime_cd_ldap)
    }

    pub fn id_smime_spq_ets_sqt_uri() -> Nid {
        Nid(ffi::NID_id_smime_spq_ets_sqt_uri)
    }

    pub fn id_smime_spq_ets_sqt_unotice() -> Nid {
        Nid(ffi::NID_id_smime_spq_ets_sqt_unotice)
    }

    pub fn id_smime_cti_ets_proofOfOrigin() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfOrigin)
    }

    pub fn id_smime_cti_ets_proofOfReceipt() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfReceipt)
    }

    pub fn id_smime_cti_ets_proofOfDelivery() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfDelivery)
    }

    pub fn id_smime_cti_ets_proofOfSender() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfSender)
    }

    pub fn id_smime_cti_ets_proofOfApproval() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfApproval)
    }

    pub fn id_smime_cti_ets_proofOfCreation() -> Nid {
        Nid(ffi::NID_id_smime_cti_ets_proofOfCreation)
    }

    pub fn friendlyName() -> Nid {
        Nid(ffi::NID_friendlyName)
    }

    pub fn localKeyID() -> Nid {
        Nid(ffi::NID_localKeyID)
    }

    pub fn ms_csp_name() -> Nid {
        Nid(ffi::NID_ms_csp_name)
    }

    pub fn LocalKeySet() -> Nid {
        Nid(ffi::NID_LocalKeySet)
    }

    pub fn x509Certificate() -> Nid {
        Nid(ffi::NID_x509Certificate)
    }

    pub fn sdsiCertificate() -> Nid {
        Nid(ffi::NID_sdsiCertificate)
    }

    pub fn x509Crl() -> Nid {
        Nid(ffi::NID_x509Crl)
    }

    pub fn pbe_WithSHA1And128BitRC4() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And128BitRC4)
    }

    pub fn pbe_WithSHA1And40BitRC4() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And40BitRC4)
    }

    pub fn pbe_WithSHA1And3_Key_TripleDES_CBC() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And3_Key_TripleDES_CBC)
    }

    pub fn pbe_WithSHA1And2_Key_TripleDES_CBC() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And2_Key_TripleDES_CBC)
    }

    pub fn pbe_WithSHA1And128BitRC2_CBC() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And128BitRC2_CBC)
    }

    pub fn pbe_WithSHA1And40BitRC2_CBC() -> Nid {
        Nid(ffi::NID_pbe_WithSHA1And40BitRC2_CBC)
    }

    pub fn keyBag() -> Nid {
        Nid(ffi::NID_keyBag)
    }

    pub fn pkcs8ShroudedKeyBag() -> Nid {
        Nid(ffi::NID_pkcs8ShroudedKeyBag)
    }

    pub fn certBag() -> Nid {
        Nid(ffi::NID_certBag)
    }

    pub fn crlBag() -> Nid {
        Nid(ffi::NID_crlBag)
    }

    pub fn secretBag() -> Nid {
        Nid(ffi::NID_secretBag)
    }

    pub fn safeContentsBag() -> Nid {
        Nid(ffi::NID_safeContentsBag)
    }

    pub fn md2() -> Nid {
        Nid(ffi::NID_md2)
    }

    pub fn md4() -> Nid {
        Nid(ffi::NID_md4)
    }

    pub fn md5() -> Nid {
        Nid(ffi::NID_md5)
    }

    pub fn md5_sha1() -> Nid {
        Nid(ffi::NID_md5_sha1)
    }

    pub fn hmacWithMD5() -> Nid {
        Nid(ffi::NID_hmacWithMD5)
    }

    pub fn hmacWithSHA1() -> Nid {
        Nid(ffi::NID_hmacWithSHA1)
    }

    pub fn hmacWithSHA224() -> Nid {
        Nid(ffi::NID_hmacWithSHA224)
    }

    pub fn hmacWithSHA256() -> Nid {
        Nid(ffi::NID_hmacWithSHA256)
    }

    pub fn hmacWithSHA384() -> Nid {
        Nid(ffi::NID_hmacWithSHA384)
    }

    pub fn hmacWithSHA512() -> Nid {
        Nid(ffi::NID_hmacWithSHA512)
    }

    pub fn rc2_cbc() -> Nid {
        Nid(ffi::NID_rc2_cbc)
    }

    pub fn rc2_ecb() -> Nid {
        Nid(ffi::NID_rc2_ecb)
    }

    pub fn rc2_cfb64() -> Nid {
        Nid(ffi::NID_rc2_cfb64)
    }

    pub fn rc2_ofb64() -> Nid {
        Nid(ffi::NID_rc2_ofb64)
    }

    pub fn rc2_40_cbc() -> Nid {
        Nid(ffi::NID_rc2_40_cbc)
    }

    pub fn rc2_64_cbc() -> Nid {
        Nid(ffi::NID_rc2_64_cbc)
    }

    pub fn rc4() -> Nid {
        Nid(ffi::NID_rc4)
    }

    pub fn rc4_40() -> Nid {
        Nid(ffi::NID_rc4_40)
    }

    pub fn des_ede3_cbc() -> Nid {
        Nid(ffi::NID_des_ede3_cbc)
    }

    pub fn rc5_cbc() -> Nid {
        Nid(ffi::NID_rc5_cbc)
    }

    pub fn rc5_ecb() -> Nid {
        Nid(ffi::NID_rc5_ecb)
    }

    pub fn rc5_cfb64() -> Nid {
        Nid(ffi::NID_rc5_cfb64)
    }

    pub fn rc5_ofb64() -> Nid {
        Nid(ffi::NID_rc5_ofb64)
    }

    pub fn ms_ext_req() -> Nid {
        Nid(ffi::NID_ms_ext_req)
    }

    pub fn ms_code_ind() -> Nid {
        Nid(ffi::NID_ms_code_ind)
    }

    pub fn ms_code_com() -> Nid {
        Nid(ffi::NID_ms_code_com)
    }

    pub fn ms_ctl_sign() -> Nid {
        Nid(ffi::NID_ms_ctl_sign)
    }

    pub fn ms_sgc() -> Nid {
        Nid(ffi::NID_ms_sgc)
    }

    pub fn ms_efs() -> Nid {
        Nid(ffi::NID_ms_efs)
    }

    pub fn ms_smartcard_login() -> Nid {
        Nid(ffi::NID_ms_smartcard_login)
    }

    pub fn ms_upn() -> Nid {
        Nid(ffi::NID_ms_upn)
    }

    pub fn idea_cbc() -> Nid {
        Nid(ffi::NID_idea_cbc)
    }

    pub fn idea_ecb() -> Nid {
        Nid(ffi::NID_idea_ecb)
    }

    pub fn idea_cfb64() -> Nid {
        Nid(ffi::NID_idea_cfb64)
    }

    pub fn idea_ofb64() -> Nid {
        Nid(ffi::NID_idea_ofb64)
    }

    pub fn bf_cbc() -> Nid {
        Nid(ffi::NID_bf_cbc)
    }

    pub fn bf_ecb() -> Nid {
        Nid(ffi::NID_bf_ecb)
    }

    pub fn bf_cfb64() -> Nid {
        Nid(ffi::NID_bf_cfb64)
    }

    pub fn bf_ofb64() -> Nid {
        Nid(ffi::NID_bf_ofb64)
    }

    pub fn id_pkix() -> Nid {
        Nid(ffi::NID_id_pkix)
    }

    pub fn id_pkix_mod() -> Nid {
        Nid(ffi::NID_id_pkix_mod)
    }

    pub fn id_pe() -> Nid {
        Nid(ffi::NID_id_pe)
    }

    pub fn id_qt() -> Nid {
        Nid(ffi::NID_id_qt)
    }

    pub fn id_kp() -> Nid {
        Nid(ffi::NID_id_kp)
    }

    pub fn id_it() -> Nid {
        Nid(ffi::NID_id_it)
    }

    pub fn id_pkip() -> Nid {
        Nid(ffi::NID_id_pkip)
    }

    pub fn id_alg() -> Nid {
        Nid(ffi::NID_id_alg)
    }

    pub fn id_cmc() -> Nid {
        Nid(ffi::NID_id_cmc)
    }

    pub fn id_on() -> Nid {
        Nid(ffi::NID_id_on)
    }

    pub fn id_pda() -> Nid {
        Nid(ffi::NID_id_pda)
    }

    pub fn id_aca() -> Nid {
        Nid(ffi::NID_id_aca)
    }

    pub fn id_qcs() -> Nid {
        Nid(ffi::NID_id_qcs)
    }

    pub fn id_cct() -> Nid {
        Nid(ffi::NID_id_cct)
    }

    pub fn id_ppl() -> Nid {
        Nid(ffi::NID_id_ppl)
    }

    pub fn id_ad() -> Nid {
        Nid(ffi::NID_id_ad)
    }

    pub fn id_pkix1_explicit_88() -> Nid {
        Nid(ffi::NID_id_pkix1_explicit_88)
    }

    pub fn id_pkix1_implicit_88() -> Nid {
        Nid(ffi::NID_id_pkix1_implicit_88)
    }

    pub fn id_pkix1_explicit_93() -> Nid {
        Nid(ffi::NID_id_pkix1_explicit_93)
    }

    pub fn id_pkix1_implicit_93() -> Nid {
        Nid(ffi::NID_id_pkix1_implicit_93)
    }

    pub fn id_mod_crmf() -> Nid {
        Nid(ffi::NID_id_mod_crmf)
    }

    pub fn id_mod_cmc() -> Nid {
        Nid(ffi::NID_id_mod_cmc)
    }

    pub fn id_mod_kea_profile_88() -> Nid {
        Nid(ffi::NID_id_mod_kea_profile_88)
    }

    pub fn id_mod_kea_profile_93() -> Nid {
        Nid(ffi::NID_id_mod_kea_profile_93)
    }

    pub fn id_mod_cmp() -> Nid {
        Nid(ffi::NID_id_mod_cmp)
    }

    pub fn id_mod_qualified_cert_88() -> Nid {
        Nid(ffi::NID_id_mod_qualified_cert_88)
    }

    pub fn id_mod_qualified_cert_93() -> Nid {
        Nid(ffi::NID_id_mod_qualified_cert_93)
    }

    pub fn id_mod_attribute_cert() -> Nid {
        Nid(ffi::NID_id_mod_attribute_cert)
    }

    pub fn id_mod_timestamp_protocol() -> Nid {
        Nid(ffi::NID_id_mod_timestamp_protocol)
    }

    pub fn id_mod_ocsp() -> Nid {
        Nid(ffi::NID_id_mod_ocsp)
    }

    pub fn id_mod_dvcs() -> Nid {
        Nid(ffi::NID_id_mod_dvcs)
    }

    pub fn id_mod_cmp2000() -> Nid {
        Nid(ffi::NID_id_mod_cmp2000)
    }

    pub fn info_access() -> Nid {
        Nid(ffi::NID_info_access)
    }

    pub fn biometricInfo() -> Nid {
        Nid(ffi::NID_biometricInfo)
    }

    pub fn qcStatements() -> Nid {
        Nid(ffi::NID_qcStatements)
    }

    pub fn ac_auditEntity() -> Nid {
        Nid(ffi::NID_ac_auditEntity)
    }

    pub fn ac_targeting() -> Nid {
        Nid(ffi::NID_ac_targeting)
    }

    pub fn aaControls() -> Nid {
        Nid(ffi::NID_aaControls)
    }

    pub fn sbgp_ipAddrBlock() -> Nid {
        Nid(ffi::NID_sbgp_ipAddrBlock)
    }

    pub fn sbgp_autonomousSysNum() -> Nid {
        Nid(ffi::NID_sbgp_autonomousSysNum)
    }

    pub fn sbgp_routerIdentifier() -> Nid {
        Nid(ffi::NID_sbgp_routerIdentifier)
    }

    pub fn ac_proxying() -> Nid {
        Nid(ffi::NID_ac_proxying)
    }

    pub fn sinfo_access() -> Nid {
        Nid(ffi::NID_sinfo_access)
    }

    pub fn proxyCertInfo() -> Nid {
        Nid(ffi::NID_proxyCertInfo)
    }

    pub fn id_qt_cps() -> Nid {
        Nid(ffi::NID_id_qt_cps)
    }

    pub fn id_qt_unotice() -> Nid {
        Nid(ffi::NID_id_qt_unotice)
    }

    pub fn textNotice() -> Nid {
        Nid(ffi::NID_textNotice)
    }

    pub fn server_auth() -> Nid {
        Nid(ffi::NID_server_auth)
    }

    pub fn client_auth() -> Nid {
        Nid(ffi::NID_client_auth)
    }

    pub fn code_sign() -> Nid {
        Nid(ffi::NID_code_sign)
    }

    pub fn email_protect() -> Nid {
        Nid(ffi::NID_email_protect)
    }

    pub fn ipsecEndSystem() -> Nid {
        Nid(ffi::NID_ipsecEndSystem)
    }

    pub fn ipsecTunnel() -> Nid {
        Nid(ffi::NID_ipsecTunnel)
    }

    pub fn ipsecUser() -> Nid {
        Nid(ffi::NID_ipsecUser)
    }

    pub fn time_stamp() -> Nid {
        Nid(ffi::NID_time_stamp)
    }

    pub fn OCSP_sign() -> Nid {
        Nid(ffi::NID_OCSP_sign)
    }

    pub fn dvcs() -> Nid {
        Nid(ffi::NID_dvcs)
    }

    pub fn id_it_caProtEncCert() -> Nid {
        Nid(ffi::NID_id_it_caProtEncCert)
    }

    pub fn id_it_signKeyPairTypes() -> Nid {
        Nid(ffi::NID_id_it_signKeyPairTypes)
    }

    pub fn id_it_encKeyPairTypes() -> Nid {
        Nid(ffi::NID_id_it_encKeyPairTypes)
    }

    pub fn id_it_preferredSymmAlg() -> Nid {
        Nid(ffi::NID_id_it_preferredSymmAlg)
    }

    pub fn id_it_caKeyUpdateInfo() -> Nid {
        Nid(ffi::NID_id_it_caKeyUpdateInfo)
    }

    pub fn id_it_currentCRL() -> Nid {
        Nid(ffi::NID_id_it_currentCRL)
    }

    pub fn id_it_unsupportedOIDs() -> Nid {
        Nid(ffi::NID_id_it_unsupportedOIDs)
    }

    pub fn id_it_subscriptionRequest() -> Nid {
        Nid(ffi::NID_id_it_subscriptionRequest)
    }

    pub fn id_it_subscriptionResponse() -> Nid {
        Nid(ffi::NID_id_it_subscriptionResponse)
    }

    pub fn id_it_keyPairParamReq() -> Nid {
        Nid(ffi::NID_id_it_keyPairParamReq)
    }

    pub fn id_it_keyPairParamRep() -> Nid {
        Nid(ffi::NID_id_it_keyPairParamRep)
    }

    pub fn id_it_revPassphrase() -> Nid {
        Nid(ffi::NID_id_it_revPassphrase)
    }

    pub fn id_it_implicitConfirm() -> Nid {
        Nid(ffi::NID_id_it_implicitConfirm)
    }

    pub fn id_it_confirmWaitTime() -> Nid {
        Nid(ffi::NID_id_it_confirmWaitTime)
    }

    pub fn id_it_origPKIMessage() -> Nid {
        Nid(ffi::NID_id_it_origPKIMessage)
    }

    pub fn id_it_suppLangTags() -> Nid {
        Nid(ffi::NID_id_it_suppLangTags)
    }

    pub fn id_regCtrl() -> Nid {
        Nid(ffi::NID_id_regCtrl)
    }

    pub fn id_regInfo() -> Nid {
        Nid(ffi::NID_id_regInfo)
    }

    pub fn id_regCtrl_regToken() -> Nid {
        Nid(ffi::NID_id_regCtrl_regToken)
    }

    pub fn id_regCtrl_authenticator() -> Nid {
        Nid(ffi::NID_id_regCtrl_authenticator)
    }

    pub fn id_regCtrl_pkiPublicationInfo() -> Nid {
        Nid(ffi::NID_id_regCtrl_pkiPublicationInfo)
    }

    pub fn id_regCtrl_pkiArchiveOptions() -> Nid {
        Nid(ffi::NID_id_regCtrl_pkiArchiveOptions)
    }

    pub fn id_regCtrl_oldCertID() -> Nid {
        Nid(ffi::NID_id_regCtrl_oldCertID)
    }

    pub fn id_regCtrl_protocolEncrKey() -> Nid {
        Nid(ffi::NID_id_regCtrl_protocolEncrKey)
    }

    pub fn id_regInfo_utf8Pairs() -> Nid {
        Nid(ffi::NID_id_regInfo_utf8Pairs)
    }

    pub fn id_regInfo_certReq() -> Nid {
        Nid(ffi::NID_id_regInfo_certReq)
    }

    pub fn id_alg_des40() -> Nid {
        Nid(ffi::NID_id_alg_des40)
    }

    pub fn id_alg_noSignature() -> Nid {
        Nid(ffi::NID_id_alg_noSignature)
    }

    pub fn id_alg_dh_sig_hmac_sha1() -> Nid {
        Nid(ffi::NID_id_alg_dh_sig_hmac_sha1)
    }

    pub fn id_alg_dh_pop() -> Nid {
        Nid(ffi::NID_id_alg_dh_pop)
    }

    pub fn id_cmc_statusInfo() -> Nid {
        Nid(ffi::NID_id_cmc_statusInfo)
    }

    pub fn id_cmc_identification() -> Nid {
        Nid(ffi::NID_id_cmc_identification)
    }

    pub fn id_cmc_identityProof() -> Nid {
        Nid(ffi::NID_id_cmc_identityProof)
    }

    pub fn id_cmc_dataReturn() -> Nid {
        Nid(ffi::NID_id_cmc_dataReturn)
    }

    pub fn id_cmc_transactionId() -> Nid {
        Nid(ffi::NID_id_cmc_transactionId)
    }

    pub fn id_cmc_senderNonce() -> Nid {
        Nid(ffi::NID_id_cmc_senderNonce)
    }

    pub fn id_cmc_recipientNonce() -> Nid {
        Nid(ffi::NID_id_cmc_recipientNonce)
    }

    pub fn id_cmc_addExtensions() -> Nid {
        Nid(ffi::NID_id_cmc_addExtensions)
    }

    pub fn id_cmc_encryptedPOP() -> Nid {
        Nid(ffi::NID_id_cmc_encryptedPOP)
    }

    pub fn id_cmc_decryptedPOP() -> Nid {
        Nid(ffi::NID_id_cmc_decryptedPOP)
    }

    pub fn id_cmc_lraPOPWitness() -> Nid {
        Nid(ffi::NID_id_cmc_lraPOPWitness)
    }

    pub fn id_cmc_getCert() -> Nid {
        Nid(ffi::NID_id_cmc_getCert)
    }

    pub fn id_cmc_getCRL() -> Nid {
        Nid(ffi::NID_id_cmc_getCRL)
    }

    pub fn id_cmc_revokeRequest() -> Nid {
        Nid(ffi::NID_id_cmc_revokeRequest)
    }

    pub fn id_cmc_regInfo() -> Nid {
        Nid(ffi::NID_id_cmc_regInfo)
    }

    pub fn id_cmc_responseInfo() -> Nid {
        Nid(ffi::NID_id_cmc_responseInfo)
    }

    pub fn id_cmc_queryPending() -> Nid {
        Nid(ffi::NID_id_cmc_queryPending)
    }

    pub fn id_cmc_popLinkRandom() -> Nid {
        Nid(ffi::NID_id_cmc_popLinkRandom)
    }

    pub fn id_cmc_popLinkWitness() -> Nid {
        Nid(ffi::NID_id_cmc_popLinkWitness)
    }

    pub fn id_cmc_confirmCertAcceptance() -> Nid {
        Nid(ffi::NID_id_cmc_confirmCertAcceptance)
    }

    pub fn id_on_personalData() -> Nid {
        Nid(ffi::NID_id_on_personalData)
    }

    pub fn id_on_permanentIdentifier() -> Nid {
        Nid(ffi::NID_id_on_permanentIdentifier)
    }

    pub fn id_pda_dateOfBirth() -> Nid {
        Nid(ffi::NID_id_pda_dateOfBirth)
    }

    pub fn id_pda_placeOfBirth() -> Nid {
        Nid(ffi::NID_id_pda_placeOfBirth)
    }

    pub fn id_pda_gender() -> Nid {
        Nid(ffi::NID_id_pda_gender)
    }

    pub fn id_pda_countryOfCitizenship() -> Nid {
        Nid(ffi::NID_id_pda_countryOfCitizenship)
    }

    pub fn id_pda_countryOfResidence() -> Nid {
        Nid(ffi::NID_id_pda_countryOfResidence)
    }

    pub fn id_aca_authenticationInfo() -> Nid {
        Nid(ffi::NID_id_aca_authenticationInfo)
    }

    pub fn id_aca_accessIdentity() -> Nid {
        Nid(ffi::NID_id_aca_accessIdentity)
    }

    pub fn id_aca_chargingIdentity() -> Nid {
        Nid(ffi::NID_id_aca_chargingIdentity)
    }

    pub fn id_aca_group() -> Nid {
        Nid(ffi::NID_id_aca_group)
    }

    pub fn id_aca_role() -> Nid {
        Nid(ffi::NID_id_aca_role)
    }

    pub fn id_aca_encAttrs() -> Nid {
        Nid(ffi::NID_id_aca_encAttrs)
    }

    pub fn id_qcs_pkixQCSyntax_v1() -> Nid {
        Nid(ffi::NID_id_qcs_pkixQCSyntax_v1)
    }

    pub fn id_cct_crs() -> Nid {
        Nid(ffi::NID_id_cct_crs)
    }

    pub fn id_cct_PKIData() -> Nid {
        Nid(ffi::NID_id_cct_PKIData)
    }

    pub fn id_cct_PKIResponse() -> Nid {
        Nid(ffi::NID_id_cct_PKIResponse)
    }

    pub fn id_ppl_anyLanguage() -> Nid {
        Nid(ffi::NID_id_ppl_anyLanguage)
    }

    pub fn id_ppl_inheritAll() -> Nid {
        Nid(ffi::NID_id_ppl_inheritAll)
    }

    pub fn Independent() -> Nid {
        Nid(ffi::NID_Independent)
    }

    pub fn ad_OCSP() -> Nid {
        Nid(ffi::NID_ad_OCSP)
    }

    pub fn ad_ca_issuers() -> Nid {
        Nid(ffi::NID_ad_ca_issuers)
    }

    pub fn ad_timeStamping() -> Nid {
        Nid(ffi::NID_ad_timeStamping)
    }

    pub fn ad_dvcs() -> Nid {
        Nid(ffi::NID_ad_dvcs)
    }

    pub fn caRepository() -> Nid {
        Nid(ffi::NID_caRepository)
    }

    pub fn id_pkix_OCSP_basic() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_basic)
    }

    pub fn id_pkix_OCSP_Nonce() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_Nonce)
    }

    pub fn id_pkix_OCSP_CrlID() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_CrlID)
    }

    pub fn id_pkix_OCSP_acceptableResponses() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_acceptableResponses)
    }

    pub fn id_pkix_OCSP_noCheck() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_noCheck)
    }

    pub fn id_pkix_OCSP_archiveCutoff() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_archiveCutoff)
    }

    pub fn id_pkix_OCSP_serviceLocator() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_serviceLocator)
    }

    pub fn id_pkix_OCSP_extendedStatus() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_extendedStatus)
    }

    pub fn id_pkix_OCSP_valid() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_valid)
    }

    pub fn id_pkix_OCSP_path() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_path)
    }

    pub fn id_pkix_OCSP_trustRoot() -> Nid {
        Nid(ffi::NID_id_pkix_OCSP_trustRoot)
    }

    pub fn algorithm() -> Nid {
        Nid(ffi::NID_algorithm)
    }

    pub fn md5WithRSA() -> Nid {
        Nid(ffi::NID_md5WithRSA)
    }

    pub fn des_ecb() -> Nid {
        Nid(ffi::NID_des_ecb)
    }

    pub fn des_cbc() -> Nid {
        Nid(ffi::NID_des_cbc)
    }

    pub fn des_ofb64() -> Nid {
        Nid(ffi::NID_des_ofb64)
    }

    pub fn des_cfb64() -> Nid {
        Nid(ffi::NID_des_cfb64)
    }

    pub fn rsaSignature() -> Nid {
        Nid(ffi::NID_rsaSignature)
    }

    pub fn dsa_2() -> Nid {
        Nid(ffi::NID_dsa_2)
    }

    pub fn dsaWithSHA() -> Nid {
        Nid(ffi::NID_dsaWithSHA)
    }

    pub fn shaWithRSAEncryption() -> Nid {
        Nid(ffi::NID_shaWithRSAEncryption)
    }

    pub fn des_ede_ecb() -> Nid {
        Nid(ffi::NID_des_ede_ecb)
    }

    pub fn des_ede3_ecb() -> Nid {
        Nid(ffi::NID_des_ede3_ecb)
    }

    pub fn des_ede_cbc() -> Nid {
        Nid(ffi::NID_des_ede_cbc)
    }

    pub fn des_ede_cfb64() -> Nid {
        Nid(ffi::NID_des_ede_cfb64)
    }

    pub fn des_ede3_cfb64() -> Nid {
        Nid(ffi::NID_des_ede3_cfb64)
    }

    pub fn des_ede_ofb64() -> Nid {
        Nid(ffi::NID_des_ede_ofb64)
    }

    pub fn des_ede3_ofb64() -> Nid {
        Nid(ffi::NID_des_ede3_ofb64)
    }

    pub fn desx_cbc() -> Nid {
        Nid(ffi::NID_desx_cbc)
    }

    pub fn sha() -> Nid {
        Nid(ffi::NID_sha)
    }

    pub fn sha1() -> Nid {
        Nid(ffi::NID_sha1)
    }

    pub fn dsaWithSHA1_2() -> Nid {
        Nid(ffi::NID_dsaWithSHA1_2)
    }

    pub fn sha1WithRSA() -> Nid {
        Nid(ffi::NID_sha1WithRSA)
    }

    pub fn ripemd160() -> Nid {
        Nid(ffi::NID_ripemd160)
    }

    pub fn ripemd160WithRSA() -> Nid {
        Nid(ffi::NID_ripemd160WithRSA)
    }

    pub fn sxnet() -> Nid {
        Nid(ffi::NID_sxnet)
    }

    pub fn X500() -> Nid {
        Nid(ffi::NID_X500)
    }

    pub fn X509() -> Nid {
        Nid(ffi::NID_X509)
    }

    pub fn commonName() -> Nid {
        Nid(ffi::NID_commonName)
    }

    pub fn surname() -> Nid {
        Nid(ffi::NID_surname)
    }

    pub fn serialNumber() -> Nid {
        Nid(ffi::NID_serialNumber)
    }

    pub fn countryName() -> Nid {
        Nid(ffi::NID_countryName)
    }

    pub fn localityName() -> Nid {
        Nid(ffi::NID_localityName)
    }

    pub fn stateOrProvinceName() -> Nid {
        Nid(ffi::NID_stateOrProvinceName)
    }

    pub fn streetAddress() -> Nid {
        Nid(ffi::NID_streetAddress)
    }

    pub fn organizationName() -> Nid {
        Nid(ffi::NID_organizationName)
    }

    pub fn organizationalUnitName() -> Nid {
        Nid(ffi::NID_organizationalUnitName)
    }

    pub fn title() -> Nid {
        Nid(ffi::NID_title)
    }

    pub fn description() -> Nid {
        Nid(ffi::NID_description)
    }

    pub fn searchGuide() -> Nid {
        Nid(ffi::NID_searchGuide)
    }

    pub fn businessCategory() -> Nid {
        Nid(ffi::NID_businessCategory)
    }

    pub fn postalAddress() -> Nid {
        Nid(ffi::NID_postalAddress)
    }

    pub fn postalCode() -> Nid {
        Nid(ffi::NID_postalCode)
    }

    pub fn postOfficeBox() -> Nid {
        Nid(ffi::NID_postOfficeBox)
    }

    pub fn physicalDeliveryOfficeName() -> Nid {
        Nid(ffi::NID_physicalDeliveryOfficeName)
    }

    pub fn telephoneNumber() -> Nid {
        Nid(ffi::NID_telephoneNumber)
    }

    pub fn telexNumber() -> Nid {
        Nid(ffi::NID_telexNumber)
    }

    pub fn teletexTerminalIdentifier() -> Nid {
        Nid(ffi::NID_teletexTerminalIdentifier)
    }

    pub fn facsimileTelephoneNumber() -> Nid {
        Nid(ffi::NID_facsimileTelephoneNumber)
    }

    pub fn x121Address() -> Nid {
        Nid(ffi::NID_x121Address)
    }

    pub fn internationaliSDNNumber() -> Nid {
        Nid(ffi::NID_internationaliSDNNumber)
    }

    pub fn registeredAddress() -> Nid {
        Nid(ffi::NID_registeredAddress)
    }

    pub fn destinationIndicator() -> Nid {
        Nid(ffi::NID_destinationIndicator)
    }

    pub fn preferredDeliveryMethod() -> Nid {
        Nid(ffi::NID_preferredDeliveryMethod)
    }

    pub fn presentationAddress() -> Nid {
        Nid(ffi::NID_presentationAddress)
    }

    pub fn supportedApplicationContext() -> Nid {
        Nid(ffi::NID_supportedApplicationContext)
    }

    pub fn member() -> Nid {
        Nid(ffi::NID_member)
    }

    pub fn owner() -> Nid {
        Nid(ffi::NID_owner)
    }

    pub fn roleOccupant() -> Nid {
        Nid(ffi::NID_roleOccupant)
    }

    pub fn seeAlso() -> Nid {
        Nid(ffi::NID_seeAlso)
    }

    pub fn userPassword() -> Nid {
        Nid(ffi::NID_userPassword)
    }

    pub fn userCertificate() -> Nid {
        Nid(ffi::NID_userCertificate)
    }

    pub fn cACertificate() -> Nid {
        Nid(ffi::NID_cACertificate)
    }

    pub fn authorityRevocationList() -> Nid {
        Nid(ffi::NID_authorityRevocationList)
    }

    pub fn certificateRevocationList() -> Nid {
        Nid(ffi::NID_certificateRevocationList)
    }

    pub fn crossCertificatePair() -> Nid {
        Nid(ffi::NID_crossCertificatePair)
    }

    pub fn name() -> Nid {
        Nid(ffi::NID_name)
    }

    pub fn givenName() -> Nid {
        Nid(ffi::NID_givenName)
    }

    pub fn initials() -> Nid {
        Nid(ffi::NID_initials)
    }

    pub fn generationQualifier() -> Nid {
        Nid(ffi::NID_generationQualifier)
    }

    pub fn x500UniqueIdentifier() -> Nid {
        Nid(ffi::NID_x500UniqueIdentifier)
    }

    pub fn dnQualifier() -> Nid {
        Nid(ffi::NID_dnQualifier)
    }

    pub fn enhancedSearchGuide() -> Nid {
        Nid(ffi::NID_enhancedSearchGuide)
    }

    pub fn protocolInformation() -> Nid {
        Nid(ffi::NID_protocolInformation)
    }

    pub fn distinguishedName() -> Nid {
        Nid(ffi::NID_distinguishedName)
    }

    pub fn uniqueMember() -> Nid {
        Nid(ffi::NID_uniqueMember)
    }

    pub fn houseIdentifier() -> Nid {
        Nid(ffi::NID_houseIdentifier)
    }

    pub fn supportedAlgorithms() -> Nid {
        Nid(ffi::NID_supportedAlgorithms)
    }

    pub fn deltaRevocationList() -> Nid {
        Nid(ffi::NID_deltaRevocationList)
    }

    pub fn dmdName() -> Nid {
        Nid(ffi::NID_dmdName)
    }

    pub fn pseudonym() -> Nid {
        Nid(ffi::NID_pseudonym)
    }

    pub fn role() -> Nid {
        Nid(ffi::NID_role)
    }

    pub fn X500algorithms() -> Nid {
        Nid(ffi::NID_X500algorithms)
    }

    pub fn rsa() -> Nid {
        Nid(ffi::NID_rsa)
    }

    pub fn mdc2WithRSA() -> Nid {
        Nid(ffi::NID_mdc2WithRSA)
    }

    pub fn mdc2() -> Nid {
        Nid(ffi::NID_mdc2)
    }

    pub fn id_ce() -> Nid {
        Nid(ffi::NID_id_ce)
    }

    pub fn subject_directory_attributes() -> Nid {
        Nid(ffi::NID_subject_directory_attributes)
    }

    pub fn subject_key_identifier() -> Nid {
        Nid(ffi::NID_subject_key_identifier)
    }

    pub fn key_usage() -> Nid {
        Nid(ffi::NID_key_usage)
    }

    pub fn private_key_usage_period() -> Nid {
        Nid(ffi::NID_private_key_usage_period)
    }

    pub fn subject_alt_name() -> Nid {
        Nid(ffi::NID_subject_alt_name)
    }

    pub fn issuer_alt_name() -> Nid {
        Nid(ffi::NID_issuer_alt_name)
    }

    pub fn basic_constraints() -> Nid {
        Nid(ffi::NID_basic_constraints)
    }

    pub fn crl_number() -> Nid {
        Nid(ffi::NID_crl_number)
    }

    pub fn crl_reason() -> Nid {
        Nid(ffi::NID_crl_reason)
    }

    pub fn invalidity_date() -> Nid {
        Nid(ffi::NID_invalidity_date)
    }

    pub fn delta_crl() -> Nid {
        Nid(ffi::NID_delta_crl)
    }

    pub fn issuing_distribution_point() -> Nid {
        Nid(ffi::NID_issuing_distribution_point)
    }

    pub fn certificate_issuer() -> Nid {
        Nid(ffi::NID_certificate_issuer)
    }

    pub fn name_constraints() -> Nid {
        Nid(ffi::NID_name_constraints)
    }

    pub fn crl_distribution_points() -> Nid {
        Nid(ffi::NID_crl_distribution_points)
    }

    pub fn certificate_policies() -> Nid {
        Nid(ffi::NID_certificate_policies)
    }

    pub fn any_policy() -> Nid {
        Nid(ffi::NID_any_policy)
    }

    pub fn policy_mappings() -> Nid {
        Nid(ffi::NID_policy_mappings)
    }

    pub fn authority_key_identifier() -> Nid {
        Nid(ffi::NID_authority_key_identifier)
    }

    pub fn policy_constraints() -> Nid {
        Nid(ffi::NID_policy_constraints)
    }

    pub fn ext_key_usage() -> Nid {
        Nid(ffi::NID_ext_key_usage)
    }

    pub fn freshest_crl() -> Nid {
        Nid(ffi::NID_freshest_crl)
    }

    pub fn inhibit_any_policy() -> Nid {
        Nid(ffi::NID_inhibit_any_policy)
    }

    pub fn target_information() -> Nid {
        Nid(ffi::NID_target_information)
    }

    pub fn no_rev_avail() -> Nid {
        Nid(ffi::NID_no_rev_avail)
    }

    pub fn anyExtendedKeyUsage() -> Nid {
        Nid(ffi::NID_anyExtendedKeyUsage)
    }

    pub fn netscape() -> Nid {
        Nid(ffi::NID_netscape)
    }

    pub fn netscape_cert_extension() -> Nid {
        Nid(ffi::NID_netscape_cert_extension)
    }

    pub fn netscape_data_type() -> Nid {
        Nid(ffi::NID_netscape_data_type)
    }

    pub fn netscape_cert_type() -> Nid {
        Nid(ffi::NID_netscape_cert_type)
    }

    pub fn netscape_base_url() -> Nid {
        Nid(ffi::NID_netscape_base_url)
    }

    pub fn netscape_revocation_url() -> Nid {
        Nid(ffi::NID_netscape_revocation_url)
    }

    pub fn netscape_ca_revocation_url() -> Nid {
        Nid(ffi::NID_netscape_ca_revocation_url)
    }

    pub fn netscape_renewal_url() -> Nid {
        Nid(ffi::NID_netscape_renewal_url)
    }

    pub fn netscape_ca_policy_url() -> Nid {
        Nid(ffi::NID_netscape_ca_policy_url)
    }

    pub fn netscape_ssl_server_name() -> Nid {
        Nid(ffi::NID_netscape_ssl_server_name)
    }

    pub fn netscape_comment() -> Nid {
        Nid(ffi::NID_netscape_comment)
    }

    pub fn netscape_cert_sequence() -> Nid {
        Nid(ffi::NID_netscape_cert_sequence)
    }

    pub fn ns_sgc() -> Nid {
        Nid(ffi::NID_ns_sgc)
    }

    pub fn org() -> Nid {
        Nid(ffi::NID_org)
    }

    pub fn dod() -> Nid {
        Nid(ffi::NID_dod)
    }

    pub fn iana() -> Nid {
        Nid(ffi::NID_iana)
    }

    pub fn Directory() -> Nid {
        Nid(ffi::NID_Directory)
    }

    pub fn Management() -> Nid {
        Nid(ffi::NID_Management)
    }

    pub fn Experimental() -> Nid {
        Nid(ffi::NID_Experimental)
    }

    pub fn Private() -> Nid {
        Nid(ffi::NID_Private)
    }

    pub fn Security() -> Nid {
        Nid(ffi::NID_Security)
    }

    pub fn SNMPv2() -> Nid {
        Nid(ffi::NID_SNMPv2)
    }

    pub fn Mail() -> Nid {
        Nid(ffi::NID_Mail)
    }

    pub fn Enterprises() -> Nid {
        Nid(ffi::NID_Enterprises)
    }

    pub fn dcObject() -> Nid {
        Nid(ffi::NID_dcObject)
    }

    pub fn mime_mhs() -> Nid {
        Nid(ffi::NID_mime_mhs)
    }

    pub fn mime_mhs_headings() -> Nid {
        Nid(ffi::NID_mime_mhs_headings)
    }

    pub fn mime_mhs_bodies() -> Nid {
        Nid(ffi::NID_mime_mhs_bodies)
    }

    pub fn id_hex_partial_message() -> Nid {
        Nid(ffi::NID_id_hex_partial_message)
    }

    pub fn id_hex_multipart_message() -> Nid {
        Nid(ffi::NID_id_hex_multipart_message)
    }

    pub fn rle_compression() -> Nid {
        Nid(ffi::NID_rle_compression)
    }

    pub fn zlib_compression() -> Nid {
        Nid(ffi::NID_zlib_compression)
    }

    pub fn aes_128_ecb() -> Nid {
        Nid(ffi::NID_aes_128_ecb)
    }

    pub fn aes_128_cbc() -> Nid {
        Nid(ffi::NID_aes_128_cbc)
    }

    pub fn aes_128_ofb128() -> Nid {
        Nid(ffi::NID_aes_128_ofb128)
    }

    pub fn aes_128_cfb128() -> Nid {
        Nid(ffi::NID_aes_128_cfb128)
    }

    pub fn id_aes128_wrap() -> Nid {
        Nid(ffi::NID_id_aes128_wrap)
    }

    pub fn aes_128_gcm() -> Nid {
        Nid(ffi::NID_aes_128_gcm)
    }

    pub fn aes_128_ccm() -> Nid {
        Nid(ffi::NID_aes_128_ccm)
    }

    pub fn id_aes128_wrap_pad() -> Nid {
        Nid(ffi::NID_id_aes128_wrap_pad)
    }

    pub fn aes_192_ecb() -> Nid {
        Nid(ffi::NID_aes_192_ecb)
    }

    pub fn aes_192_cbc() -> Nid {
        Nid(ffi::NID_aes_192_cbc)
    }

    pub fn aes_192_ofb128() -> Nid {
        Nid(ffi::NID_aes_192_ofb128)
    }

    pub fn aes_192_cfb128() -> Nid {
        Nid(ffi::NID_aes_192_cfb128)
    }

    pub fn id_aes192_wrap() -> Nid {
        Nid(ffi::NID_id_aes192_wrap)
    }

    pub fn aes_192_gcm() -> Nid {
        Nid(ffi::NID_aes_192_gcm)
    }

    pub fn aes_192_ccm() -> Nid {
        Nid(ffi::NID_aes_192_ccm)
    }

    pub fn id_aes192_wrap_pad() -> Nid {
        Nid(ffi::NID_id_aes192_wrap_pad)
    }

    pub fn aes_256_ecb() -> Nid {
        Nid(ffi::NID_aes_256_ecb)
    }

    pub fn aes_256_cbc() -> Nid {
        Nid(ffi::NID_aes_256_cbc)
    }

    pub fn aes_256_ofb128() -> Nid {
        Nid(ffi::NID_aes_256_ofb128)
    }

    pub fn aes_256_cfb128() -> Nid {
        Nid(ffi::NID_aes_256_cfb128)
    }

    pub fn id_aes256_wrap() -> Nid {
        Nid(ffi::NID_id_aes256_wrap)
    }

    pub fn aes_256_gcm() -> Nid {
        Nid(ffi::NID_aes_256_gcm)
    }

    pub fn aes_256_ccm() -> Nid {
        Nid(ffi::NID_aes_256_ccm)
    }

    pub fn id_aes256_wrap_pad() -> Nid {
        Nid(ffi::NID_id_aes256_wrap_pad)
    }

    pub fn aes_128_cfb1() -> Nid {
        Nid(ffi::NID_aes_128_cfb1)
    }

    pub fn aes_192_cfb1() -> Nid {
        Nid(ffi::NID_aes_192_cfb1)
    }

    pub fn aes_256_cfb1() -> Nid {
        Nid(ffi::NID_aes_256_cfb1)
    }

    pub fn aes_128_cfb8() -> Nid {
        Nid(ffi::NID_aes_128_cfb8)
    }

    pub fn aes_192_cfb8() -> Nid {
        Nid(ffi::NID_aes_192_cfb8)
    }

    pub fn aes_256_cfb8() -> Nid {
        Nid(ffi::NID_aes_256_cfb8)
    }

    pub fn aes_128_ctr() -> Nid {
        Nid(ffi::NID_aes_128_ctr)
    }

    pub fn aes_192_ctr() -> Nid {
        Nid(ffi::NID_aes_192_ctr)
    }

    pub fn aes_256_ctr() -> Nid {
        Nid(ffi::NID_aes_256_ctr)
    }

    pub fn aes_128_xts() -> Nid {
        Nid(ffi::NID_aes_128_xts)
    }

    pub fn aes_256_xts() -> Nid {
        Nid(ffi::NID_aes_256_xts)
    }

    pub fn des_cfb1() -> Nid {
        Nid(ffi::NID_des_cfb1)
    }

    pub fn des_cfb8() -> Nid {
        Nid(ffi::NID_des_cfb8)
    }

    pub fn des_ede3_cfb1() -> Nid {
        Nid(ffi::NID_des_ede3_cfb1)
    }

    pub fn des_ede3_cfb8() -> Nid {
        Nid(ffi::NID_des_ede3_cfb8)
    }

    pub fn sha256() -> Nid {
        Nid(ffi::NID_sha256)
    }

    pub fn sha384() -> Nid {
        Nid(ffi::NID_sha384)
    }

    pub fn sha512() -> Nid {
        Nid(ffi::NID_sha512)
    }

    pub fn sha224() -> Nid {
        Nid(ffi::NID_sha224)
    }

    pub fn dsa_with_SHA224() -> Nid {
        Nid(ffi::NID_dsa_with_SHA224)
    }

    pub fn dsa_with_SHA256() -> Nid {
        Nid(ffi::NID_dsa_with_SHA256)
    }

    pub fn hold_instruction_code() -> Nid {
        Nid(ffi::NID_hold_instruction_code)
    }

    pub fn hold_instruction_none() -> Nid {
        Nid(ffi::NID_hold_instruction_none)
    }

    pub fn hold_instruction_call_issuer() -> Nid {
        Nid(ffi::NID_hold_instruction_call_issuer)
    }

    pub fn hold_instruction_reject() -> Nid {
        Nid(ffi::NID_hold_instruction_reject)
    }

    pub fn data() -> Nid {
        Nid(ffi::NID_data)
    }

    pub fn pss() -> Nid {
        Nid(ffi::NID_pss)
    }

    pub fn ucl() -> Nid {
        Nid(ffi::NID_ucl)
    }

    pub fn pilot() -> Nid {
        Nid(ffi::NID_pilot)
    }

    pub fn pilotAttributeType() -> Nid {
        Nid(ffi::NID_pilotAttributeType)
    }

    pub fn pilotAttributeSyntax() -> Nid {
        Nid(ffi::NID_pilotAttributeSyntax)
    }

    pub fn pilotObjectClass() -> Nid {
        Nid(ffi::NID_pilotObjectClass)
    }

    pub fn pilotGroups() -> Nid {
        Nid(ffi::NID_pilotGroups)
    }

    pub fn iA5StringSyntax() -> Nid {
        Nid(ffi::NID_iA5StringSyntax)
    }

    pub fn caseIgnoreIA5StringSyntax() -> Nid {
        Nid(ffi::NID_caseIgnoreIA5StringSyntax)
    }

    pub fn pilotObject() -> Nid {
        Nid(ffi::NID_pilotObject)
    }

    pub fn pilotPerson() -> Nid {
        Nid(ffi::NID_pilotPerson)
    }

    pub fn account() -> Nid {
        Nid(ffi::NID_account)
    }

    pub fn document() -> Nid {
        Nid(ffi::NID_document)
    }

    pub fn room() -> Nid {
        Nid(ffi::NID_room)
    }

    pub fn documentSeries() -> Nid {
        Nid(ffi::NID_documentSeries)
    }

    pub fn Domain() -> Nid {
        Nid(ffi::NID_Domain)
    }

    pub fn rFC822localPart() -> Nid {
        Nid(ffi::NID_rFC822localPart)
    }

    pub fn dNSDomain() -> Nid {
        Nid(ffi::NID_dNSDomain)
    }

    pub fn domainRelatedObject() -> Nid {
        Nid(ffi::NID_domainRelatedObject)
    }

    pub fn friendlyCountry() -> Nid {
        Nid(ffi::NID_friendlyCountry)
    }

    pub fn simpleSecurityObject() -> Nid {
        Nid(ffi::NID_simpleSecurityObject)
    }

    pub fn pilotOrganization() -> Nid {
        Nid(ffi::NID_pilotOrganization)
    }

    pub fn pilotDSA() -> Nid {
        Nid(ffi::NID_pilotDSA)
    }

    pub fn qualityLabelledData() -> Nid {
        Nid(ffi::NID_qualityLabelledData)
    }

    pub fn userId() -> Nid {
        Nid(ffi::NID_userId)
    }

    pub fn textEncodedORAddress() -> Nid {
        Nid(ffi::NID_textEncodedORAddress)
    }

    pub fn rfc822Mailbox() -> Nid {
        Nid(ffi::NID_rfc822Mailbox)
    }

    pub fn info() -> Nid {
        Nid(ffi::NID_info)
    }

    pub fn favouriteDrink() -> Nid {
        Nid(ffi::NID_favouriteDrink)
    }

    pub fn roomNumber() -> Nid {
        Nid(ffi::NID_roomNumber)
    }

    pub fn photo() -> Nid {
        Nid(ffi::NID_photo)
    }

    pub fn userClass() -> Nid {
        Nid(ffi::NID_userClass)
    }

    pub fn host() -> Nid {
        Nid(ffi::NID_host)
    }

    pub fn manager() -> Nid {
        Nid(ffi::NID_manager)
    }

    pub fn documentIdentifier() -> Nid {
        Nid(ffi::NID_documentIdentifier)
    }

    pub fn documentTitle() -> Nid {
        Nid(ffi::NID_documentTitle)
    }

    pub fn documentVersion() -> Nid {
        Nid(ffi::NID_documentVersion)
    }

    pub fn documentAuthor() -> Nid {
        Nid(ffi::NID_documentAuthor)
    }

    pub fn documentLocation() -> Nid {
        Nid(ffi::NID_documentLocation)
    }

    pub fn homeTelephoneNumber() -> Nid {
        Nid(ffi::NID_homeTelephoneNumber)
    }

    pub fn secretary() -> Nid {
        Nid(ffi::NID_secretary)
    }

    pub fn otherMailbox() -> Nid {
        Nid(ffi::NID_otherMailbox)
    }

    pub fn lastModifiedTime() -> Nid {
        Nid(ffi::NID_lastModifiedTime)
    }

    pub fn lastModifiedBy() -> Nid {
        Nid(ffi::NID_lastModifiedBy)
    }

    pub fn domainComponent() -> Nid {
        Nid(ffi::NID_domainComponent)
    }

    pub fn aRecord() -> Nid {
        Nid(ffi::NID_aRecord)
    }

    pub fn pilotAttributeType27() -> Nid {
        Nid(ffi::NID_pilotAttributeType27)
    }

    pub fn mXRecord() -> Nid {
        Nid(ffi::NID_mXRecord)
    }

    pub fn nSRecord() -> Nid {
        Nid(ffi::NID_nSRecord)
    }

    pub fn sOARecord() -> Nid {
        Nid(ffi::NID_sOARecord)
    }

    pub fn cNAMERecord() -> Nid {
        Nid(ffi::NID_cNAMERecord)
    }

    pub fn associatedDomain() -> Nid {
        Nid(ffi::NID_associatedDomain)
    }

    pub fn associatedName() -> Nid {
        Nid(ffi::NID_associatedName)
    }

    pub fn homePostalAddress() -> Nid {
        Nid(ffi::NID_homePostalAddress)
    }

    pub fn personalTitle() -> Nid {
        Nid(ffi::NID_personalTitle)
    }

    pub fn mobileTelephoneNumber() -> Nid {
        Nid(ffi::NID_mobileTelephoneNumber)
    }

    pub fn pagerTelephoneNumber() -> Nid {
        Nid(ffi::NID_pagerTelephoneNumber)
    }

    pub fn friendlyCountryName() -> Nid {
        Nid(ffi::NID_friendlyCountryName)
    }

    pub fn organizationalStatus() -> Nid {
        Nid(ffi::NID_organizationalStatus)
    }

    pub fn janetMailbox() -> Nid {
        Nid(ffi::NID_janetMailbox)
    }

    pub fn mailPreferenceOption() -> Nid {
        Nid(ffi::NID_mailPreferenceOption)
    }

    pub fn buildingName() -> Nid {
        Nid(ffi::NID_buildingName)
    }

    pub fn dSAQuality() -> Nid {
        Nid(ffi::NID_dSAQuality)
    }

    pub fn singleLevelQuality() -> Nid {
        Nid(ffi::NID_singleLevelQuality)
    }

    pub fn subtreeMinimumQuality() -> Nid {
        Nid(ffi::NID_subtreeMinimumQuality)
    }

    pub fn subtreeMaximumQuality() -> Nid {
        Nid(ffi::NID_subtreeMaximumQuality)
    }

    pub fn personalSignature() -> Nid {
        Nid(ffi::NID_personalSignature)
    }

    pub fn dITRedirect() -> Nid {
        Nid(ffi::NID_dITRedirect)
    }

    pub fn audio() -> Nid {
        Nid(ffi::NID_audio)
    }

    pub fn documentPublisher() -> Nid {
        Nid(ffi::NID_documentPublisher)
    }

    pub fn id_set() -> Nid {
        Nid(ffi::NID_id_set)
    }

    pub fn set_ctype() -> Nid {
        Nid(ffi::NID_set_ctype)
    }

    pub fn set_msgExt() -> Nid {
        Nid(ffi::NID_set_msgExt)
    }

    pub fn set_attr() -> Nid {
        Nid(ffi::NID_set_attr)
    }

    pub fn set_policy() -> Nid {
        Nid(ffi::NID_set_policy)
    }

    pub fn set_certExt() -> Nid {
        Nid(ffi::NID_set_certExt)
    }

    pub fn set_brand() -> Nid {
        Nid(ffi::NID_set_brand)
    }

    pub fn setct_PANData() -> Nid {
        Nid(ffi::NID_setct_PANData)
    }

    pub fn setct_PANToken() -> Nid {
        Nid(ffi::NID_setct_PANToken)
    }

    pub fn setct_PANOnly() -> Nid {
        Nid(ffi::NID_setct_PANOnly)
    }

    pub fn setct_OIData() -> Nid {
        Nid(ffi::NID_setct_OIData)
    }

    pub fn setct_PI() -> Nid {
        Nid(ffi::NID_setct_PI)
    }

    pub fn setct_PIData() -> Nid {
        Nid(ffi::NID_setct_PIData)
    }

    pub fn setct_PIDataUnsigned() -> Nid {
        Nid(ffi::NID_setct_PIDataUnsigned)
    }

    pub fn setct_HODInput() -> Nid {
        Nid(ffi::NID_setct_HODInput)
    }

    pub fn setct_AuthResBaggage() -> Nid {
        Nid(ffi::NID_setct_AuthResBaggage)
    }

    pub fn setct_AuthRevReqBaggage() -> Nid {
        Nid(ffi::NID_setct_AuthRevReqBaggage)
    }

    pub fn setct_AuthRevResBaggage() -> Nid {
        Nid(ffi::NID_setct_AuthRevResBaggage)
    }

    pub fn setct_CapTokenSeq() -> Nid {
        Nid(ffi::NID_setct_CapTokenSeq)
    }

    pub fn setct_PInitResData() -> Nid {
        Nid(ffi::NID_setct_PInitResData)
    }

    pub fn setct_PI_TBS() -> Nid {
        Nid(ffi::NID_setct_PI_TBS)
    }

    pub fn setct_PResData() -> Nid {
        Nid(ffi::NID_setct_PResData)
    }

    pub fn setct_AuthReqTBS() -> Nid {
        Nid(ffi::NID_setct_AuthReqTBS)
    }

    pub fn setct_AuthResTBS() -> Nid {
        Nid(ffi::NID_setct_AuthResTBS)
    }

    pub fn setct_AuthResTBSX() -> Nid {
        Nid(ffi::NID_setct_AuthResTBSX)
    }

    pub fn setct_AuthTokenTBS() -> Nid {
        Nid(ffi::NID_setct_AuthTokenTBS)
    }

    pub fn setct_CapTokenData() -> Nid {
        Nid(ffi::NID_setct_CapTokenData)
    }

    pub fn setct_CapTokenTBS() -> Nid {
        Nid(ffi::NID_setct_CapTokenTBS)
    }

    pub fn setct_AcqCardCodeMsg() -> Nid {
        Nid(ffi::NID_setct_AcqCardCodeMsg)
    }

    pub fn setct_AuthRevReqTBS() -> Nid {
        Nid(ffi::NID_setct_AuthRevReqTBS)
    }

    pub fn setct_AuthRevResData() -> Nid {
        Nid(ffi::NID_setct_AuthRevResData)
    }

    pub fn setct_AuthRevResTBS() -> Nid {
        Nid(ffi::NID_setct_AuthRevResTBS)
    }

    pub fn setct_CapReqTBS() -> Nid {
        Nid(ffi::NID_setct_CapReqTBS)
    }

    pub fn setct_CapReqTBSX() -> Nid {
        Nid(ffi::NID_setct_CapReqTBSX)
    }

    pub fn setct_CapResData() -> Nid {
        Nid(ffi::NID_setct_CapResData)
    }

    pub fn setct_CapRevReqTBS() -> Nid {
        Nid(ffi::NID_setct_CapRevReqTBS)
    }

    pub fn setct_CapRevReqTBSX() -> Nid {
        Nid(ffi::NID_setct_CapRevReqTBSX)
    }

    pub fn setct_CapRevResData() -> Nid {
        Nid(ffi::NID_setct_CapRevResData)
    }

    pub fn setct_CredReqTBS() -> Nid {
        Nid(ffi::NID_setct_CredReqTBS)
    }

    pub fn setct_CredReqTBSX() -> Nid {
        Nid(ffi::NID_setct_CredReqTBSX)
    }

    pub fn setct_CredResData() -> Nid {
        Nid(ffi::NID_setct_CredResData)
    }

    pub fn setct_CredRevReqTBS() -> Nid {
        Nid(ffi::NID_setct_CredRevReqTBS)
    }

    pub fn setct_CredRevReqTBSX() -> Nid {
        Nid(ffi::NID_setct_CredRevReqTBSX)
    }

    pub fn setct_CredRevResData() -> Nid {
        Nid(ffi::NID_setct_CredRevResData)
    }

    pub fn setct_PCertReqData() -> Nid {
        Nid(ffi::NID_setct_PCertReqData)
    }

    pub fn setct_PCertResTBS() -> Nid {
        Nid(ffi::NID_setct_PCertResTBS)
    }

    pub fn setct_BatchAdminReqData() -> Nid {
        Nid(ffi::NID_setct_BatchAdminReqData)
    }

    pub fn setct_BatchAdminResData() -> Nid {
        Nid(ffi::NID_setct_BatchAdminResData)
    }

    pub fn setct_CardCInitResTBS() -> Nid {
        Nid(ffi::NID_setct_CardCInitResTBS)
    }

    pub fn setct_MeAqCInitResTBS() -> Nid {
        Nid(ffi::NID_setct_MeAqCInitResTBS)
    }

    pub fn setct_RegFormResTBS() -> Nid {
        Nid(ffi::NID_setct_RegFormResTBS)
    }

    pub fn setct_CertReqData() -> Nid {
        Nid(ffi::NID_setct_CertReqData)
    }

    pub fn setct_CertReqTBS() -> Nid {
        Nid(ffi::NID_setct_CertReqTBS)
    }

    pub fn setct_CertResData() -> Nid {
        Nid(ffi::NID_setct_CertResData)
    }

    pub fn setct_CertInqReqTBS() -> Nid {
        Nid(ffi::NID_setct_CertInqReqTBS)
    }

    pub fn setct_ErrorTBS() -> Nid {
        Nid(ffi::NID_setct_ErrorTBS)
    }

    pub fn setct_PIDualSignedTBE() -> Nid {
        Nid(ffi::NID_setct_PIDualSignedTBE)
    }

    pub fn setct_PIUnsignedTBE() -> Nid {
        Nid(ffi::NID_setct_PIUnsignedTBE)
    }

    pub fn setct_AuthReqTBE() -> Nid {
        Nid(ffi::NID_setct_AuthReqTBE)
    }

    pub fn setct_AuthResTBE() -> Nid {
        Nid(ffi::NID_setct_AuthResTBE)
    }

    pub fn setct_AuthResTBEX() -> Nid {
        Nid(ffi::NID_setct_AuthResTBEX)
    }

    pub fn setct_AuthTokenTBE() -> Nid {
        Nid(ffi::NID_setct_AuthTokenTBE)
    }

    pub fn setct_CapTokenTBE() -> Nid {
        Nid(ffi::NID_setct_CapTokenTBE)
    }

    pub fn setct_CapTokenTBEX() -> Nid {
        Nid(ffi::NID_setct_CapTokenTBEX)
    }

    pub fn setct_AcqCardCodeMsgTBE() -> Nid {
        Nid(ffi::NID_setct_AcqCardCodeMsgTBE)
    }

    pub fn setct_AuthRevReqTBE() -> Nid {
        Nid(ffi::NID_setct_AuthRevReqTBE)
    }

    pub fn setct_AuthRevResTBE() -> Nid {
        Nid(ffi::NID_setct_AuthRevResTBE)
    }

    pub fn setct_AuthRevResTBEB() -> Nid {
        Nid(ffi::NID_setct_AuthRevResTBEB)
    }

    pub fn setct_CapReqTBE() -> Nid {
        Nid(ffi::NID_setct_CapReqTBE)
    }

    pub fn setct_CapReqTBEX() -> Nid {
        Nid(ffi::NID_setct_CapReqTBEX)
    }

    pub fn setct_CapResTBE() -> Nid {
        Nid(ffi::NID_setct_CapResTBE)
    }

    pub fn setct_CapRevReqTBE() -> Nid {
        Nid(ffi::NID_setct_CapRevReqTBE)
    }

    pub fn setct_CapRevReqTBEX() -> Nid {
        Nid(ffi::NID_setct_CapRevReqTBEX)
    }

    pub fn setct_CapRevResTBE() -> Nid {
        Nid(ffi::NID_setct_CapRevResTBE)
    }

    pub fn setct_CredReqTBE() -> Nid {
        Nid(ffi::NID_setct_CredReqTBE)
    }

    pub fn setct_CredReqTBEX() -> Nid {
        Nid(ffi::NID_setct_CredReqTBEX)
    }

    pub fn setct_CredResTBE() -> Nid {
        Nid(ffi::NID_setct_CredResTBE)
    }

    pub fn setct_CredRevReqTBE() -> Nid {
        Nid(ffi::NID_setct_CredRevReqTBE)
    }

    pub fn setct_CredRevReqTBEX() -> Nid {
        Nid(ffi::NID_setct_CredRevReqTBEX)
    }

    pub fn setct_CredRevResTBE() -> Nid {
        Nid(ffi::NID_setct_CredRevResTBE)
    }

    pub fn setct_BatchAdminReqTBE() -> Nid {
        Nid(ffi::NID_setct_BatchAdminReqTBE)
    }

    pub fn setct_BatchAdminResTBE() -> Nid {
        Nid(ffi::NID_setct_BatchAdminResTBE)
    }

    pub fn setct_RegFormReqTBE() -> Nid {
        Nid(ffi::NID_setct_RegFormReqTBE)
    }

    pub fn setct_CertReqTBE() -> Nid {
        Nid(ffi::NID_setct_CertReqTBE)
    }

    pub fn setct_CertReqTBEX() -> Nid {
        Nid(ffi::NID_setct_CertReqTBEX)
    }

    pub fn setct_CertResTBE() -> Nid {
        Nid(ffi::NID_setct_CertResTBE)
    }

    pub fn setct_CRLNotificationTBS() -> Nid {
        Nid(ffi::NID_setct_CRLNotificationTBS)
    }

    pub fn setct_CRLNotificationResTBS() -> Nid {
        Nid(ffi::NID_setct_CRLNotificationResTBS)
    }

    pub fn setct_BCIDistributionTBS() -> Nid {
        Nid(ffi::NID_setct_BCIDistributionTBS)
    }

    pub fn setext_genCrypt() -> Nid {
        Nid(ffi::NID_setext_genCrypt)
    }

    pub fn setext_miAuth() -> Nid {
        Nid(ffi::NID_setext_miAuth)
    }

    pub fn setext_pinSecure() -> Nid {
        Nid(ffi::NID_setext_pinSecure)
    }

    pub fn setext_pinAny() -> Nid {
        Nid(ffi::NID_setext_pinAny)
    }

    pub fn setext_track2() -> Nid {
        Nid(ffi::NID_setext_track2)
    }

    pub fn setext_cv() -> Nid {
        Nid(ffi::NID_setext_cv)
    }

    pub fn set_policy_root() -> Nid {
        Nid(ffi::NID_set_policy_root)
    }

    pub fn setCext_hashedRoot() -> Nid {
        Nid(ffi::NID_setCext_hashedRoot)
    }

    pub fn setCext_certType() -> Nid {
        Nid(ffi::NID_setCext_certType)
    }

    pub fn setCext_merchData() -> Nid {
        Nid(ffi::NID_setCext_merchData)
    }

    pub fn setCext_cCertRequired() -> Nid {
        Nid(ffi::NID_setCext_cCertRequired)
    }

    pub fn setCext_tunneling() -> Nid {
        Nid(ffi::NID_setCext_tunneling)
    }

    pub fn setCext_setExt() -> Nid {
        Nid(ffi::NID_setCext_setExt)
    }

    pub fn setCext_setQualf() -> Nid {
        Nid(ffi::NID_setCext_setQualf)
    }

    pub fn setCext_PGWYcapabilities() -> Nid {
        Nid(ffi::NID_setCext_PGWYcapabilities)
    }

    pub fn setCext_TokenIdentifier() -> Nid {
        Nid(ffi::NID_setCext_TokenIdentifier)
    }

    pub fn setCext_Track2Data() -> Nid {
        Nid(ffi::NID_setCext_Track2Data)
    }

    pub fn setCext_TokenType() -> Nid {
        Nid(ffi::NID_setCext_TokenType)
    }

    pub fn setCext_IssuerCapabilities() -> Nid {
        Nid(ffi::NID_setCext_IssuerCapabilities)
    }

    pub fn setAttr_Cert() -> Nid {
        Nid(ffi::NID_setAttr_Cert)
    }

    pub fn setAttr_PGWYcap() -> Nid {
        Nid(ffi::NID_setAttr_PGWYcap)
    }

    pub fn setAttr_TokenType() -> Nid {
        Nid(ffi::NID_setAttr_TokenType)
    }

    pub fn setAttr_IssCap() -> Nid {
        Nid(ffi::NID_setAttr_IssCap)
    }

    pub fn set_rootKeyThumb() -> Nid {
        Nid(ffi::NID_set_rootKeyThumb)
    }

    pub fn set_addPolicy() -> Nid {
        Nid(ffi::NID_set_addPolicy)
    }

    pub fn setAttr_Token_EMV() -> Nid {
        Nid(ffi::NID_setAttr_Token_EMV)
    }

    pub fn setAttr_Token_B0Prime() -> Nid {
        Nid(ffi::NID_setAttr_Token_B0Prime)
    }

    pub fn setAttr_IssCap_CVM() -> Nid {
        Nid(ffi::NID_setAttr_IssCap_CVM)
    }

    pub fn setAttr_IssCap_T2() -> Nid {
        Nid(ffi::NID_setAttr_IssCap_T2)
    }

    pub fn setAttr_IssCap_Sig() -> Nid {
        Nid(ffi::NID_setAttr_IssCap_Sig)
    }

    pub fn setAttr_GenCryptgrm() -> Nid {
        Nid(ffi::NID_setAttr_GenCryptgrm)
    }

    pub fn setAttr_T2Enc() -> Nid {
        Nid(ffi::NID_setAttr_T2Enc)
    }

    pub fn setAttr_T2cleartxt() -> Nid {
        Nid(ffi::NID_setAttr_T2cleartxt)
    }

    pub fn setAttr_TokICCsig() -> Nid {
        Nid(ffi::NID_setAttr_TokICCsig)
    }

    pub fn setAttr_SecDevSig() -> Nid {
        Nid(ffi::NID_setAttr_SecDevSig)
    }

    pub fn set_brand_IATA_ATA() -> Nid {
        Nid(ffi::NID_set_brand_IATA_ATA)
    }

    pub fn set_brand_Diners() -> Nid {
        Nid(ffi::NID_set_brand_Diners)
    }

    pub fn set_brand_AmericanExpress() -> Nid {
        Nid(ffi::NID_set_brand_AmericanExpress)
    }

    pub fn set_brand_JCB() -> Nid {
        Nid(ffi::NID_set_brand_JCB)
    }

    pub fn set_brand_Visa() -> Nid {
        Nid(ffi::NID_set_brand_Visa)
    }

    pub fn set_brand_MasterCard() -> Nid {
        Nid(ffi::NID_set_brand_MasterCard)
    }

    pub fn set_brand_Novus() -> Nid {
        Nid(ffi::NID_set_brand_Novus)
    }

    pub fn des_cdmf() -> Nid {
        Nid(ffi::NID_des_cdmf)
    }

    pub fn rsaOAEPEncryptionSET() -> Nid {
        Nid(ffi::NID_rsaOAEPEncryptionSET)
    }

    pub fn ipsec3() -> Nid {
        Nid(ffi::NID_ipsec3)
    }

    pub fn ipsec4() -> Nid {
        Nid(ffi::NID_ipsec4)
    }

    pub fn whirlpool() -> Nid {
        Nid(ffi::NID_whirlpool)
    }

    pub fn cryptopro() -> Nid {
        Nid(ffi::NID_cryptopro)
    }

    pub fn cryptocom() -> Nid {
        Nid(ffi::NID_cryptocom)
    }

    pub fn id_GostR3411_94_with_GostR3410_2001() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_with_GostR3410_2001)
    }

    pub fn id_GostR3411_94_with_GostR3410_94() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_with_GostR3410_94)
    }

    pub fn id_GostR3411_94() -> Nid {
        Nid(ffi::NID_id_GostR3411_94)
    }

    pub fn id_HMACGostR3411_94() -> Nid {
        Nid(ffi::NID_id_HMACGostR3411_94)
    }

    pub fn id_GostR3410_2001() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001)
    }

    pub fn id_GostR3410_94() -> Nid {
        Nid(ffi::NID_id_GostR3410_94)
    }

    pub fn id_Gost28147_89() -> Nid {
        Nid(ffi::NID_id_Gost28147_89)
    }

    pub fn gost89_cnt() -> Nid {
        Nid(ffi::NID_gost89_cnt)
    }

    pub fn id_Gost28147_89_MAC() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_MAC)
    }

    pub fn id_GostR3411_94_prf() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_prf)
    }

    pub fn id_GostR3410_2001DH() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001DH)
    }

    pub fn id_GostR3410_94DH() -> Nid {
        Nid(ffi::NID_id_GostR3410_94DH)
    }

    pub fn id_Gost28147_89_CryptoPro_KeyMeshing() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_KeyMeshing)
    }

    pub fn id_Gost28147_89_None_KeyMeshing() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_None_KeyMeshing)
    }

    pub fn id_GostR3411_94_TestParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_TestParamSet)
    }

    pub fn id_GostR3411_94_CryptoProParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_CryptoProParamSet)
    }

    pub fn id_Gost28147_89_TestParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_TestParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_A_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_A_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_B_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_B_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_C_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_C_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_D_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_D_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet)
    }

    pub fn id_Gost28147_89_CryptoPro_RIC_1_ParamSet() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet)
    }

    pub fn id_GostR3410_94_TestParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_TestParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_A_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_A_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_B_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_B_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_C_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_C_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_D_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_D_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_XchA_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_XchA_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_XchB_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_XchB_ParamSet)
    }

    pub fn id_GostR3410_94_CryptoPro_XchC_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_CryptoPro_XchC_ParamSet)
    }

    pub fn id_GostR3410_2001_TestParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_TestParamSet)
    }

    pub fn id_GostR3410_2001_CryptoPro_A_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_CryptoPro_A_ParamSet)
    }

    pub fn id_GostR3410_2001_CryptoPro_B_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_CryptoPro_B_ParamSet)
    }

    pub fn id_GostR3410_2001_CryptoPro_C_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_CryptoPro_C_ParamSet)
    }

    pub fn id_GostR3410_2001_CryptoPro_XchA_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet)
    }

    pub fn id_GostR3410_2001_CryptoPro_XchB_ParamSet() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet)
    }

    pub fn id_GostR3410_94_a() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_a)
    }

    pub fn id_GostR3410_94_aBis() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_aBis)
    }

    pub fn id_GostR3410_94_b() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_b)
    }

    pub fn id_GostR3410_94_bBis() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_bBis)
    }

    pub fn id_Gost28147_89_cc() -> Nid {
        Nid(ffi::NID_id_Gost28147_89_cc)
    }

    pub fn id_GostR3410_94_cc() -> Nid {
        Nid(ffi::NID_id_GostR3410_94_cc)
    }

    pub fn id_GostR3410_2001_cc() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_cc)
    }

    pub fn id_GostR3411_94_with_GostR3410_94_cc() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_with_GostR3410_94_cc)
    }

    pub fn id_GostR3411_94_with_GostR3410_2001_cc() -> Nid {
        Nid(ffi::NID_id_GostR3411_94_with_GostR3410_2001_cc)
    }

    pub fn id_GostR3410_2001_ParamSet_cc() -> Nid {
        Nid(ffi::NID_id_GostR3410_2001_ParamSet_cc)
    }

    pub fn camellia_128_cbc() -> Nid {
        Nid(ffi::NID_camellia_128_cbc)
    }

    pub fn camellia_192_cbc() -> Nid {
        Nid(ffi::NID_camellia_192_cbc)
    }

    pub fn camellia_256_cbc() -> Nid {
        Nid(ffi::NID_camellia_256_cbc)
    }

    pub fn id_camellia128_wrap() -> Nid {
        Nid(ffi::NID_id_camellia128_wrap)
    }

    pub fn id_camellia192_wrap() -> Nid {
        Nid(ffi::NID_id_camellia192_wrap)
    }

    pub fn id_camellia256_wrap() -> Nid {
        Nid(ffi::NID_id_camellia256_wrap)
    }

    pub fn camellia_128_ecb() -> Nid {
        Nid(ffi::NID_camellia_128_ecb)
    }

    pub fn camellia_128_ofb128() -> Nid {
        Nid(ffi::NID_camellia_128_ofb128)
    }

    pub fn camellia_128_cfb128() -> Nid {
        Nid(ffi::NID_camellia_128_cfb128)
    }

    pub fn camellia_192_ecb() -> Nid {
        Nid(ffi::NID_camellia_192_ecb)
    }

    pub fn camellia_192_ofb128() -> Nid {
        Nid(ffi::NID_camellia_192_ofb128)
    }

    pub fn camellia_192_cfb128() -> Nid {
        Nid(ffi::NID_camellia_192_cfb128)
    }

    pub fn camellia_256_ecb() -> Nid {
        Nid(ffi::NID_camellia_256_ecb)
    }

    pub fn camellia_256_ofb128() -> Nid {
        Nid(ffi::NID_camellia_256_ofb128)
    }

    pub fn camellia_256_cfb128() -> Nid {
        Nid(ffi::NID_camellia_256_cfb128)
    }

    pub fn camellia_128_cfb1() -> Nid {
        Nid(ffi::NID_camellia_128_cfb1)
    }

    pub fn camellia_192_cfb1() -> Nid {
        Nid(ffi::NID_camellia_192_cfb1)
    }

    pub fn camellia_256_cfb1() -> Nid {
        Nid(ffi::NID_camellia_256_cfb1)
    }

    pub fn camellia_128_cfb8() -> Nid {
        Nid(ffi::NID_camellia_128_cfb8)
    }

    pub fn camellia_192_cfb8() -> Nid {
        Nid(ffi::NID_camellia_192_cfb8)
    }

    pub fn camellia_256_cfb8() -> Nid {
        Nid(ffi::NID_camellia_256_cfb8)
    }

    pub fn kisa() -> Nid {
        Nid(ffi::NID_kisa)
    }

    pub fn seed_ecb() -> Nid {
        Nid(ffi::NID_seed_ecb)
    }

    pub fn seed_cbc() -> Nid {
        Nid(ffi::NID_seed_cbc)
    }

    pub fn seed_cfb128() -> Nid {
        Nid(ffi::NID_seed_cfb128)
    }

    pub fn seed_ofb128() -> Nid {
        Nid(ffi::NID_seed_ofb128)
    }

    pub fn hmac() -> Nid {
        Nid(ffi::NID_hmac)
    }

    pub fn cmac() -> Nid {
        Nid(ffi::NID_cmac)
    }

    pub fn rc4_hmac_md5() -> Nid {
        Nid(ffi::NID_rc4_hmac_md5)
    }

    pub fn aes_128_cbc_hmac_sha1() -> Nid {
        Nid(ffi::NID_aes_128_cbc_hmac_sha1)
    }

    pub fn aes_192_cbc_hmac_sha1() -> Nid {
        Nid(ffi::NID_aes_192_cbc_hmac_sha1)
    }

    pub fn aes_256_cbc_hmac_sha1() -> Nid {
        Nid(ffi::NID_aes_256_cbc_hmac_sha1)
    }

    pub fn aes_128_cbc_hmac_sha256() -> Nid {
        Nid(ffi::NID_aes_128_cbc_hmac_sha256)
    }

    pub fn aes_192_cbc_hmac_sha256() -> Nid {
        Nid(ffi::NID_aes_192_cbc_hmac_sha256)
    }

    pub fn aes_256_cbc_hmac_sha256() -> Nid {
        Nid(ffi::NID_aes_256_cbc_hmac_sha256)
    }

    pub fn dhpublicnumber() -> Nid {
        Nid(ffi::NID_dhpublicnumber)
    }

    pub fn brainpoolP160r1() -> Nid {
        Nid(ffi::NID_brainpoolP160r1)
    }

    pub fn brainpoolP160t1() -> Nid {
        Nid(ffi::NID_brainpoolP160t1)
    }

    pub fn brainpoolP192r1() -> Nid {
        Nid(ffi::NID_brainpoolP192r1)
    }

    pub fn brainpoolP192t1() -> Nid {
        Nid(ffi::NID_brainpoolP192t1)
    }

    pub fn brainpoolP224r1() -> Nid {
        Nid(ffi::NID_brainpoolP224r1)
    }

    pub fn brainpoolP224t1() -> Nid {
        Nid(ffi::NID_brainpoolP224t1)
    }

    pub fn brainpoolP256r1() -> Nid {
        Nid(ffi::NID_brainpoolP256r1)
    }

    pub fn brainpoolP256t1() -> Nid {
        Nid(ffi::NID_brainpoolP256t1)
    }

    pub fn brainpoolP320r1() -> Nid {
        Nid(ffi::NID_brainpoolP320r1)
    }

    pub fn brainpoolP320t1() -> Nid {
        Nid(ffi::NID_brainpoolP320t1)
    }

    pub fn brainpoolP384r1() -> Nid {
        Nid(ffi::NID_brainpoolP384r1)
    }

    pub fn brainpoolP384t1() -> Nid {
        Nid(ffi::NID_brainpoolP384t1)
    }

    pub fn brainpoolP512r1() -> Nid {
        Nid(ffi::NID_brainpoolP512r1)
    }

    pub fn brainpoolP512t1() -> Nid {
        Nid(ffi::NID_brainpoolP512t1)
    }

    pub fn dhSinglePass_stdDH_sha1kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_stdDH_sha1kdf_scheme)
    }

    pub fn dhSinglePass_stdDH_sha224kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_stdDH_sha224kdf_scheme)
    }

    pub fn dhSinglePass_stdDH_sha256kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_stdDH_sha256kdf_scheme)
    }

    pub fn dhSinglePass_stdDH_sha384kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_stdDH_sha384kdf_scheme)
    }

    pub fn dhSinglePass_stdDH_sha512kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_stdDH_sha512kdf_scheme)
    }

    pub fn dhSinglePass_cofactorDH_sha1kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_cofactorDH_sha1kdf_scheme)
    }

    pub fn dhSinglePass_cofactorDH_sha224kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_cofactorDH_sha224kdf_scheme)
    }

    pub fn dhSinglePass_cofactorDH_sha256kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_cofactorDH_sha256kdf_scheme)
    }

    pub fn dhSinglePass_cofactorDH_sha384kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_cofactorDH_sha384kdf_scheme)
    }

    pub fn dhSinglePass_cofactorDH_sha512kdf_scheme() -> Nid {
        Nid(ffi::NID_dhSinglePass_cofactorDH_sha512kdf_scheme)
    }

    pub fn dh_std_kdf() -> Nid {
        Nid(ffi::NID_dh_std_kdf)
    }

    pub fn dh_cofactor_kdf() -> Nid {
        Nid(ffi::NID_dh_cofactor_kdf)
    }

    pub fn ct_precert_scts() -> Nid {
        Nid(ffi::NID_ct_precert_scts)
    }

    pub fn ct_precert_poison() -> Nid {
        Nid(ffi::NID_ct_precert_poison)
    }

    pub fn ct_precert_signer() -> Nid {
        Nid(ffi::NID_ct_precert_signer)
    }

    pub fn ct_cert_scts() -> Nid {
        Nid(ffi::NID_ct_cert_scts)
    }

    pub fn jurisdictionLocalityName() -> Nid {
        Nid(ffi::NID_jurisdictionLocalityName)
    }

    pub fn jurisdictionStateOrProvinceName() -> Nid {
        Nid(ffi::NID_jurisdictionStateOrProvinceName)
    }

    pub fn jurisdictionCountryName() -> Nid {
        Nid(ffi::NID_jurisdictionCountryName)
    }
}