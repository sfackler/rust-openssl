use libc::{c_long, time_t, c_char};
use std::ptr;

use time;
use ffi;
use ssl::error::SslError;
use std::ffi::CString;
use std::slice;

#[cfg(test)]
mod tests;

pub struct Asn1Time {
    handle: *mut ffi::ASN1_TIME,
    owned: bool,
}

impl Asn1Time {
    /// Wraps existing ASN1_TIME and takes ownership
    pub fn new(handle: *mut ffi::ASN1_TIME) -> Asn1Time {
        Asn1Time {
            handle: handle,
            owned: true,
        }
    }

    /// Create a new Asn1Time from a given time_t.
    fn from_time_t(t: time_t) -> Asn1Time {
        let v = unsafe { ffi::ASN1_TIME_set(ptr::null_mut(), t) };
        /* failures here are only due to allocation issues, so panicing is appropriate */
        assert!(!v.is_null());

        Asn1Time {
            handle: v,
            owned: true,
        }
    }

    /// Create a new Asn1Time from an absolute timespec
    pub fn from_tm(t: time::Tm) -> Result<Asn1Time, SslError> {
        let t = tm_to_asn1_string(t);
        let v = Asn1Time::from_time_t(0);
        try_ssl!(unsafe {
            ffi::ASN1_TIME_set_string(
                v.get_handle(),
                /* unwraping is OK because we know tm_to_asn1_string() does not generate embedded
                 * nulls */
                CString::new(t).unwrap().as_ptr() as *const c_char
            )
        });
        Ok(v)
    }

    fn new_with_period(period: u64) -> Result<Asn1Time, SslError> {
        ffi::init();

        let handle = unsafe {
            try_ssl_null!(ffi::X509_gmtime_adj(ptr::null_mut(), period as c_long))
        };
        Ok(Asn1Time::new(handle))
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, SslError> {
        Asn1Time::new_with_period(days as u64 * 60 * 60 * 24)
    }

    /// Returns raw handle
    pub unsafe fn get_handle(&self) -> *mut ffi::ASN1_TIME {
        return self.handle;
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
        unsafe {
            let v : &ffi::ASN1_TIME = &*(self.handle);
            slice::from_raw_parts(v.data, v.length as usize)
        }
    }

    pub fn as_tm(&self) -> Result<time::Tm, String> {
        let typ = unsafe {
            let v: &ffi::ASN1_TIME = &*(self.handle);
            v.typ
        };
        match typ {
            ffi::V_ASN1_GENERALIZEDTIME => {
                asn1_string_to_tm(self.as_bytes(), 4)
            },
            ffi::V_ASN1_UTCTIME => {
                asn1_string_to_tm(self.as_bytes(), 2)
            },
            _ => {
                Err(format!("Unknown type {}", typ))
            }
        }
    }
}

impl Drop for Asn1Time {
    fn drop(&mut self) {
        if self.owned {
            unsafe { ffi::ASN1_TIME_free(self.handle) };
        }
    }
}

/// Given a timespec, generate an ASN.1 string suitible for passing to openssl.
///
/// Note that this does lose the seconds offset from the timezone, but note that most (all?)
/// timezone's lack a seconds offset in any case.
pub fn tm_to_asn1_string(t: time::Tm) -> String
{
    let tz_hours = t.tm_utcoff / 60 / 60;
    let tz_min = (t.tm_utcoff).abs() / 60 % 60;
    /* Note that strftime is undesirable as it lacks support for nanoseconds */
    /* YYYYMMDDHHMMSS.nsZ */
    /*       YYYY MM   DD   HH   MM   SS   .ns   Z */
    format!("{:04}{:02}{:02}{:02}{:02}{:02}.{:09}{:+03}{:02}",
            t.tm_year + 1900,
            t.tm_mon + 1,
            t.tm_mday,
            t.tm_hour,
            t.tm_min,
            t.tm_sec,
            t.tm_nsec,
            tz_hours,
            tz_min)
}

fn parse_n_digit<I>(b: &mut I, ct: usize, name: &str) -> Result<i32, String>
    where I: Iterator<Item = u8>
{
    let mut res: u32 = 0;

    for i in 0..ct {
        res *= 10;
        let c = try!(b.next().ok_or(format!("Digit {} out of {} in {} not found", i, ct, name))) as char;
        res += try!(c.to_digit(10).ok_or(format!("Digit {} out of {} in {} is not convertable: {}",
                                                 i, ct, name, c)));
    }

    Ok(res as i32)
}

/// Read digits until we get a non-digit character, then correct the value to be as if we parsed
/// @n values.
///
/// If digits exist after @ct, eat them without changing result
fn parse_decimal<I>(b: &mut I, ct: usize) -> Result<(i32, u8), String>
    where I: Iterator<Item = u8>
{
    let mut res: u32 = 0;
    for i in 0..ct {
        let v = try!(b.next().ok_or(format!("Digit or character {} in decimal not found", i)));
        let c = v as char;
        if c.is_numeric() {
            res *= 10;
            res += try!(c.to_digit(10).ok_or(format!("Digit {} out of {} in decimal is not convertable: {}",
                                                     i, ct, c)));
        } else {
            res *= 10u32.pow((ct - i) as u32);
            return Ok((res as i32, v))
        }
    }

    /* We've got all the data we need, but there might be digits left */
    loop {
        let v = try!(b.next().ok_or(format!("Digit or character trailing decimal not found")));
        if !(v as char).is_numeric() {
            return Ok((res as i32, v))
        }
    }
}

/// Given an ASN.1 formated time, generate a timespec
///
/// If @short_year is true, assumes the year is 2 digits and applies a heuristic to guess the real
/// year.
///
/// Note that the returned Tm does not fill out tm_wday, tm_yday, or tm_isdst (they are -1, 0, and
/// 0 respectively), so users of the result should be cautious that they don't rely on those
/// fields.
pub fn asn1_string_to_tm(s: &[u8], year_len: usize) -> Result<time::Tm, String>
{
    let mut b = s.iter().cloned();

    let mut y = try!(parse_n_digit(&mut b, year_len, "year"));
    let year = if year_len < 4 {
        if y < 70 {
            y += 100;
        }
        y
    } else {
        y - 1900
    };

    let month = try!(parse_n_digit(&mut b, 2, "month"));
    let day = try!(parse_n_digit(&mut b, 2, "day"));
    let hour = try!(parse_n_digit(&mut b, 2, "hour"));
    let minute = try!(parse_n_digit(&mut b, 2, "minute"));
    let second = try!(parse_n_digit(&mut b, 2, "second"));

    let c = try!(b.next().ok_or("Character after seconds missing"));
    let (nano, c) = if (c as char) == '.' {
        /* parse nano seconds */
        try!(parse_decimal(&mut b, 9))
    } else {
        (0, c)
    };

    /* use the extra char 'c' and the reset of iterator to get the timezone */
    let tz_sec = match c as char {
        'Z' => {
            0
        },
        '+' | '-' => {
            let tz_hours = try!(parse_n_digit(&mut b, 2, "tz hours"));
            let tz_min = try!(parse_n_digit(&mut b, 2, "tz minutes"));
            let neg = if c as char == '+' {
                1
            } else {
                -1
            };
            neg * ((tz_hours * 60) + tz_min) * 60
        },
        _ => {
            return Err(format!("Unexpected character {} in timezone", c));
        }
    };

    Ok(time::Tm {
        tm_sec: second,
        tm_min: minute,
        tm_hour: hour,
        tm_mday: day,
        tm_mon: month - 1,
        tm_year: year,
        tm_nsec: nano,
        tm_utcoff: tz_sec,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0,
    })
}
