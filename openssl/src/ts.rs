use std::ptr;

use crate::{
    asn1::{Asn1GeneralizedTimeRef, Asn1IntegerRef, Asn1ObjectRef, Asn1OctetStringRef},
    cvt_p,
    stack::StackRef,
    x509::{GeneralNameRef, X509AlgorithmRef, X509Extension},
};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use crate::{error::ErrorStack, pkcs7::Pkcs7Ref};

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_TST_INFO;
    fn drop = ffi::TS_TST_INFO_free;
    fn clone = ffi::TS_TST_INFO_dup;

    /// High level TS_TST_INFO wrapper
    ///
    /// Time Stamp Token is set of hash of data, hash algorithm used to calculate the hash, and etc.
    /// Time Stamp Token is used to prove that hash of data exists before the time this info is generated (genTime).
    /// Normally this data is generated via sending TimeStampReq.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-8
    pub struct TsTstInfo;
    /// Reference to [`TsTstInfo`]
    ///
    /// [`TsTstInfo`]:struct.TsTstInfo.html
    pub struct TsTstInfoRef;
}

impl TsTstInfoRef {
    to_der! {
        /// Serializes this TsTstInfo using DER.
        #[corresponds(i2d_TS_TST_INFO)]
        to_der,
        ffi::i2d_TS_TST_INFO
    }
}

impl TsTstInfo {
    from_der! {
        /// Deserializes a DER-encoded TsTstInfo structure.
        #[corresponds(d2i_TS_TST_INFO)]
        from_der,
        TsTstInfo,
        ffi::d2i_TS_TST_INFO
    }

    /// create TsTstInfo from pkcs7 directly.
    pub fn from_pkcs7(pkcs7: &Pkcs7Ref) -> Result<Self, ErrorStack> {
        Ok(TsTstInfo(unsafe {
            cvt_p(ffi::PKCS7_to_TS_TST_INFO(pkcs7.as_ptr()))?
        }))
    }
}

impl TsTstInfoRef {
    /// version describes version of timestamp token.
    /// version can only be 1 for RFC3161.
    #[corresponds(TS_TST_INFO_get_version)]
    pub fn version(&self) -> i64 {
        let version = unsafe { ffi::TS_TST_INFO_get_version(self.as_ptr()) };
        if version < 0 {
            panic!("Invariant Violation. TS_TST_INFO_get_version must return 1");
        } else {
            version
        }
    }

    /// returns TSAPolicyId.
    ///
    /// policyId is TSA's policy under which response was generated.
    #[corresponds(TS_TST_INFO_get_policy_id)]
    pub fn policy_id(&self) -> &Asn1ObjectRef {
        unsafe {
            let policy_id_ptr = ffi::TS_TST_INFO_get_policy_id(self.as_ptr());
            if policy_id_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_policy_id must not return null");
            }
            Asn1ObjectRef::from_ptr(policy_id_ptr)
        }
    }

    #[corresponds(TS_TST_INFO_get_msg_imprint)]
    pub fn msg_imprint(&self) -> &TsMessageImprintRef {
        unsafe {
            let msg_imprint_ptr = ffi::TS_TST_INFO_get_msg_imprint(self.as_ptr());
            if msg_imprint_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_msg_imprint must not return null");
            }
            TsMessageImprintRef::from_ptr(msg_imprint_ptr)
        }
    }

    /// serial is 160 bits at most.
    #[corresponds(TS_TST_INFO_get_serial)]
    pub fn serial(&self) -> &Asn1IntegerRef {
        unsafe {
            let serial_ptr = ffi::TS_TST_INFO_get_serial(self.as_ptr());
            if serial_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_serial must not return null");
            }
            Asn1IntegerRef::from_ptr(serial_ptr as *mut _)
        }
    }

    /// returns genTime.
    ///
    /// genTime is the time at which the timestamp is generated.
    /// genTime must be UTC time. The last character of genTime is always Z (Zulu timezone).
    /// Granularity of time is not limited. However if the precision does not need to be better than
    /// seconds, it SHOULD be limitted to one second.
    #[corresponds(TS_TST_INFO_get_time)]
    pub fn time(&self) -> &Asn1GeneralizedTimeRef {
        unsafe {
            let gen_time_tpr = ffi::TS_TST_INFO_get_time(self.as_ptr());
            if gen_time_tpr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_time must not return null");
            }
            Asn1GeneralizedTimeRef::from_ptr(gen_time_tpr as *mut _)
        }
    }

    #[corresponds(TS_TST_INFO_get_accuracy)]
    pub fn accuracy(&self) -> Option<&TsAccuracyRef> {
        unsafe {
            let accuracy_ptr = ffi::TS_TST_INFO_get_accuracy(self.as_ptr());
            if accuracy_ptr.is_null() {
                None
            } else {
                Some(TsAccuracyRef::from_ptr(accuracy_ptr as *mut _))
            }
        }
    }

    /// returns ordering.
    /// default is FALSE
    #[corresponds(TS_TST_INFO_get_ordering)]
    pub fn ordering(&self) -> bool {
        // TS_TST_INFO_get_ordering returns just 1 or 0
        // default is false
        if unsafe { ffi::TS_TST_INFO_get_ordering(self.as_ptr()) } > 0 {
            true
        } else {
            false
        }
    }

    #[corresponds(TS_TST_INFO_get_nonce)]
    pub fn nonce(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let serial_ptr = ffi::TS_TST_INFO_get_nonce(self.as_ptr());
            if serial_ptr.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(serial_ptr as *mut _))
            }
        }
    }

    #[corresponds(TS_TST_INFO_get_tsa)]
    pub fn tsa(&self) -> Option<&GeneralNameRef> {
        unsafe {
            let tsa_ptr = ffi::TS_TST_INFO_get_tsa(self.as_ptr());
            if tsa_ptr.is_null() {
                None
            } else {
                Some(GeneralNameRef::from_ptr(tsa_ptr))
            }
        }
    }

    #[corresponds(TS_TST_INFO_get_exts)]
    pub fn exts(&self) -> Option<&StackRef<X509Extension>> {
        unsafe {
            let ext_ptr = ffi::TS_TST_INFO_get_exts(self.as_ptr());
            if ext_ptr.is_null() {
                None
            } else {
                Some(StackRef::<X509Extension>::from_ptr(ext_ptr))
            }
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;
    fn clone = ffi::TS_MSG_IMPRINT_dup;

    /// High level TS_MSG_IMPRINT wrapper
    ///
    /// messageImprint contains a hash algorithm and hased message to be or to have been time-stamped.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-4
    pub struct TsMessageImprint;
    /// Reference to [`TsMessageImprint`]
    ///
    /// [`TsMessageImprint`]:struct.TsMessageImprint.html
    pub struct TsMessageImprintRef;
}

impl TsMessageImprintRef {
    to_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(i2d_TS_MSG_IMPRINT)]
        to_der,
        ffi::i2d_TS_MSG_IMPRINT
    }

    #[corresponds(TS_MSG_IMPRINT_get_algo)]
    pub fn algo(&self) -> &X509AlgorithmRef {
        unsafe { X509AlgorithmRef::from_ptr(ffi::TS_MSG_IMPRINT_get_algo(self.as_ptr())) }
    }

    #[corresponds(TS_MSG_IMPRINT_get_msg)]
    pub fn msg(&self) -> &Asn1OctetStringRef {
        unsafe { Asn1OctetStringRef::from_ptr(ffi::TS_MSG_IMPRINT_get_msg(self.as_ptr())) }
    }
}

impl TsMessageImprint {
    from_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(d2i_TS_MSG_IMPRINT)]
        from_der,
        TsMessageImprint,
        ffi::d2i_TS_MSG_IMPRINT
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_ACCURACY;
    fn drop = ffi::TS_ACCURACY_free;
    fn clone = ffi::TS_ACCURACY_dup;

    /// High level TS_ACCURACY wrapper
    ///
    /// Accuracy represents the time deviation around the genTime.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-9
    pub struct TsAccuracy;
    /// Reference to [`TsAccuracy`]
    ///
    /// [`TsAccuracy`]:struct.TsAccuracy.html
    pub struct TsAccuracyRef;
}

impl TsAccuracyRef {
    #[corresponds(TS_ACCURACY_get_seconds)]
    pub fn seconds(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_seconds(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }

    #[corresponds(TS_ACCURACY_get_millis)]
    pub fn millis(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_millis(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }

    #[corresponds(TS_ACCURACY_get_micros)]
    pub fn micros(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_micros(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }
}

impl TsAccuracy {
    from_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(d2i_TS_ACCURACY)]
        from_der,
        TsAccuracy,
        ffi::d2i_TS_ACCURACY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::CmsContentInfo;
    use crate::pkcs7::Pkcs7;
    const RFC3161_DATA: &'static [u8] = include_bytes!("../test/sample_rfc3161_cms.der");
    const TST_INFO: &'static [u8] = include_bytes!("../test/tst_info.der");

    #[test]
    fn test_from_pkcs7() {
        let tst_info = {
            let pkcs7 = Pkcs7::from_der(RFC3161_DATA).unwrap();
            TsTstInfo::from_pkcs7(&pkcs7).unwrap()
        };

        test_get(&tst_info);
        test_accuracy(&tst_info);
        test_message_imprint(&tst_info);
        test_extensions(&tst_info);
    }

    #[test]
    fn test_from_cms() {
        let tst_info = {
            let cms = CmsContentInfo::from_der(RFC3161_DATA).unwrap();
            TsTstInfo::from_der(cms.content().unwrap().unwrap()).unwrap()
        };

        test_get(&tst_info);
        test_accuracy(&tst_info);
        test_message_imprint(&tst_info);
        test_extensions(&tst_info);
    }

    #[test]
    fn test_from_der_to_der() {
        let der = {
            let tst_info = TsTstInfo::from_der(TST_INFO).unwrap();
            let der = tst_info.to_der().unwrap();
            assert_eq!(TST_INFO, der);
            // testing dupe.
            tst_info.to_owned()
        }
        .to_der()
        .unwrap();
        assert_eq!(TST_INFO, der);
    }

    fn test_get(tst_info: &TsTstInfo) {
        assert_eq!(tst_info.version(), 1);
        assert_eq!(
            // Basic Time-Stamping policy
            "1.3.6.1.4.1.38064.1.3.6.1",
            tst_info.policy_id().to_string()
        );
        assert_eq!(
            "4828232355673314455",
            tst_info.serial().to_bn().unwrap().to_string()
        );
        assert_eq!(
            "20211214111051Z",
            tst_info.time().as_utf8().unwrap().to_string()
        );
        assert_eq!(tst_info.ordering(), false);
        assert_eq!(
            "-1578146648116833895",
            tst_info.nonce().unwrap().to_bn().unwrap().to_string()
        );
        assert!(tst_info.tsa().is_none());
    }

    fn test_accuracy(tst_info: &TsTstInfo) {
        let acc = {
            let acc = tst_info.accuracy().unwrap();
            // testing dupe.
            acc.to_owned()
        };

        assert_eq!("1", acc.seconds().unwrap().to_bn().unwrap().to_string());
        assert!(acc.millis().is_none());
        assert!(acc.micros().is_none());
    }

    fn test_message_imprint(tst_info: &TsTstInfo) {
        let msg_imprint = {
            let msg_imprint = tst_info.msg_imprint();
            msg_imprint.to_owned()
        };

        let algo = msg_imprint.algo();
        let msg = msg_imprint.msg();

        assert_eq!("sha256", algo.object().nid().long_name().unwrap());
        assert!(msg.as_slice().len() > 0);
    }

    fn test_extensions(tst_info: &TsTstInfo) {
        // Unfortunately. We currently do not have tst_info with extensions set.
        assert!(tst_info.exts().is_none());
    }
}
