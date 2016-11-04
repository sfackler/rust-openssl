use ffi;

use cvt_p;
use error::ErrorStack;
use nid::Nid;

type_!(EcKey, EcKeyRef, ffi::EC_KEY, ffi::EC_KEY_free);

impl EcKey {
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe { cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey) }
    }
}

#[cfg(test)]
mod test {
    use nid;
    use super::*;

    #[test]
    fn new_by_curve_name() {
        EcKey::new_by_curve_name(nid::X9_62_PRIME256V1).unwrap();
    }
}
