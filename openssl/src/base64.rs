use std::ptr;
use std::slice;

use ffi;
use error::ErrorStack;
use {cvt_p, cvt};

/// Specify the behavior of the encoder and decoder regarding the
/// handling of newlines.
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum LineMode {
    /// Tell the encoder not to generate newlines. Tell the decoder to
    /// generate an error if a newline is encountered.
    SingleLine,
    /// Allow the encoder to generate newlines if the output is longer
    /// than an arbitrary limit (usually 64 characters). Tell the
    /// decoder to ignore newlines.
    MultiLine,
}

/// Encode `data` in base64. If `newlines` is true then the data is
/// encoded with line breaks.
pub fn encode(data: &[u8], line_mode: LineMode) -> Result<Vec<u8>, ErrorStack> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let bio = unsafe { try!(cvt_p(ffi::BIO_new(ffi::BIO_f_base64()))) };

    let bio = Bio(bio);

    if line_mode == LineMode::SingleLine {
        unsafe {
            ffi::BIO_set_flags(bio.as_ptr(), ffi::BIO_FLAGS_BASE64_NO_NL);
        }
    }

    unsafe {
        // Add some memory to hold the result
        let mem = try!(cvt_p(ffi::BIO_new(ffi::BIO_s_mem())));

        try!(cvt_p(ffi::BIO_push(bio.as_ptr(), mem)));

        // Write `data` to the BIO
        try!(cvt(ffi::BIO_write(bio.as_ptr(),
                                data.as_ptr() as *const _,
                                data.len() as _)));

        // Flush output
        try!(cvt(ffi::BIO_flush(bio.as_ptr())));

        // Build a slice from the output
        let mut ptr = ptr::null_mut();
        let len = ffi::BIO_get_mem_data(bio.as_ptr(), &mut ptr);

        let s =
            slice::from_raw_parts(ptr as *const _ as *const _, len as usize);

        Ok(s.to_owned())
    }
}

/// Decode `data` from base64. If `nl` is true then the decoder will
/// accept newlines in the base64 data.
pub fn decode(data: &[u8], line_mode: LineMode) -> Result<Vec<u8>, ErrorStack> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let bio = unsafe { try!(cvt_p(ffi::BIO_new(ffi::BIO_f_base64()))) };

    let bio = Bio(bio);

    unsafe {
        // Put `data` in a mem_buf
        let mem_buf = try!(cvt_p(ffi::BIO_new_mem_buf(data.as_ptr() as *const _,
                                                      data.len() as _)));

        try!(cvt_p(ffi::BIO_push(bio.as_ptr(), mem_buf)));

        if line_mode == LineMode::SingleLine {
            ffi::BIO_set_flags(bio.as_ptr(), ffi::BIO_FLAGS_BASE64_NO_NL);
        }
    }

    // Allocate output buffer, we know that base64 data will be at
    // least 4/3 bigger than the raw input
    let mut data = vec![0; (data.len() * 3 + 3) / 4];

    unsafe {
        let len = try!(cvt(ffi::BIO_read(bio.as_ptr(),
                                         data.as_mut_ptr() as *mut _,
                                         data.len() as _)));

        data.truncate(len as usize);
    }

    Ok(data)
}

struct Bio(*mut ffi::BIO);

impl Bio {
    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }
}

impl Drop for Bio {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

#[test]
fn test_encode() {
    use self::LineMode::{SingleLine, MultiLine};

    assert_eq!(encode(b"", SingleLine).unwrap(), b"");

    assert_eq!(encode(&[0], SingleLine).unwrap(), b"AA==");

    assert_eq!(encode(b"rust-openssl", SingleLine).unwrap(),
               b"cnVzdC1vcGVuc3Ns");

    assert_eq!(encode(b"The quick brown fox jumps over the lazy dog",
                      SingleLine).unwrap(),
               b"VGhlIHF1aWNrIGJyb3duIGZveCBqdW\
                 1wcyBvdmVyIHRoZSBsYXp5IGRvZw==" as &[u8]);

    let long = b"Lorem ipsum dolor sit amet, consectetur \
                 adipiscing elit, sed do eiusmod tempor \
                 incididunt ut labore et dolore magna aliqua.";

    let base64_oneline = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnN\
                           lY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIG\
                           VpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib\
                           3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu";

    assert_eq!(encode(long, SingleLine).unwrap(), base64_oneline as &[u8]);

    let base64_multiline = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvb\
                             nNlY3RldHVyIGFkaXBpc2Np\n\
                             bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yI\
                             GluY2lkaWR1bnQgdXQgbGFi\n\
                             b3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu\n";

    assert_eq!(encode(long, MultiLine).unwrap(), base64_multiline as &[u8]);
}

#[test]
fn test_decode() {
    use self::LineMode::{SingleLine, MultiLine};

    assert_eq!(decode(b"", SingleLine).unwrap(), b"");

    assert_eq!(decode(b"cnVzdC1v\ncGVuc3Ns", MultiLine).unwrap(),
               b"rust-openssl");

    assert!(decode(b"cnVzdC1v\ncGVuc3Ns", SingleLine).is_err());

    assert!(decode(b"invalid !!", SingleLine).is_err());
}

/// Make sure we can always decode ourselves
#[test]
fn test_encode_decode() {
    use self::LineMode::{SingleLine, MultiLine};

    let input: &[&[u8]] = &[
        b"test",
        b"Lorem ipsum dolor sit amet, consectetur \
          adipiscing elit, sed do eiusmod tempor \
          incididunt ut labore et dolore magna aliqua.",
        b"",
        &[ 0x00, 0xff, 0x42, 0x00, 0x56],
        &[ 0xab; 1024],
    ];

    for &i in input {
        let encoded = encode(i, SingleLine).unwrap();
        let decoded = decode(&encoded, SingleLine).unwrap();
        assert_eq!(i, &decoded as &[u8]);

        let encoded = encode(i, MultiLine).unwrap();
        let decoded = decode(&encoded, MultiLine).unwrap();
        assert_eq!(i, &decoded as &[u8]);
    }
}
