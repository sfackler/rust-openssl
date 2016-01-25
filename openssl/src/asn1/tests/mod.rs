use time;

fn check_convert(s: &str, t: time::Tm, ylen: usize)
{
    use super::{asn1_string_to_tm,tm_to_asn1_string};

    let g_t = asn1_string_to_tm(s.as_bytes(), ylen).expect("asn1 time decode failed");
    assert_eq!(g_t, t);

    let g_s = tm_to_asn1_string(t);

    println!("> {} ", g_s);

    assert_eq!(asn1_string_to_tm(g_s.as_bytes(), 4).expect("generate asn1 time decode failed"), t);
}

#[test]
fn asn1_time_str_convert() {
    //       YYYYMMddHHmmSSZ
    let s = "21340103020508Z";
    let t = time::Tm {
        tm_sec: 8,
        tm_min: 5,
        tm_hour: 2,
        tm_mday: 3,
        tm_mon: 0,
        tm_year: 2134 - 1900,

        tm_nsec: 0,
        tm_utcoff: 0,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    };

    check_convert(s, t, 4);

    //             YYMMddHHmmSS+HHmm
    check_convert("990102030405+0706", time::Tm {
        tm_sec:5,
        tm_min:4,
        tm_hour: 3,
        tm_mday: 2,
        tm_mon: 0,
        tm_year: 1999 - 1900,

        tm_nsec: 0,
        tm_utcoff: ((7 * 60) + 6) * 60,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    }, 2);

    //             YYYYMMddHHmmSS.ns-HHmm
    check_convert("19891131535455.23452-1011", time::Tm {
        tm_sec: 55,
        tm_min: 54,
        tm_hour: 53,
        tm_mday: 31,
        tm_mon: 10,
        tm_year: 1989 - 1900,

        //       123456789
        tm_nsec: 234520000,

        tm_utcoff: -((10 * 60) + 11) * 60,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    }, 4);

    //             YYYYMMddHHmmSS.ns-HHmm
    check_convert("19891131535455.1234567898-1011", time::Tm {
        tm_sec: 55,
        tm_min: 54,
        tm_hour: 53,
        tm_mday: 31,
        tm_mon: 10,
        tm_year: 1989 - 1900,

        tm_nsec: 123456789,

        tm_utcoff: -((10 * 60) + 11) * 60,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    }, 4);

    //             YYYYMMddHHmmSS.ns-HHmm
    check_convert("19891131535455.123456789-1011", time::Tm {
        tm_sec: 55,
        tm_min: 54,
        tm_hour: 53,
        tm_mday: 31,
        tm_mon: 10,
        tm_year: 1989 - 1900,

        tm_nsec: 123456789,

        tm_utcoff: -((10 * 60) + 11) * 60,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    }, 4);
}

fn asn1_time_roundtrip(t: time::Tm) {
    use super::Asn1Time;
    use super::tm_to_asn1_string;
    println!("> {} ", tm_to_asn1_string(t));
    assert_eq!(Asn1Time::from_tm(t).expect("could not create Asn1Time from Tm")
               .as_tm().expect("could not get Tm from Asn1Time"), t);
}

#[test]
fn asn1_time_tm() {
    /* check that we can round trip a Tm through Asn1Time */

    asn1_time_roundtrip(time::Tm {
        tm_sec: 55,
        tm_min: 54,
        tm_hour: 23,
        tm_mday: 31,
        tm_mon: 11,
        tm_year: 1989 - 1900,

        tm_nsec: 123456789,

        tm_utcoff: -((10 * 60) + 11) * 60,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    });

    asn1_time_roundtrip(time::Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 23,
        tm_mday: 31,
        tm_mon: 11,
        tm_year: 1950 - 1900,

        tm_nsec: 1239,

        tm_utcoff: 0,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    });

    asn1_time_roundtrip(time::Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 23,
        tm_mday: 31,
        tm_mon: 11,
        tm_year: 2040 - 1900,

        tm_nsec: 0,

        tm_utcoff: 0,

        tm_isdst: -1,
        tm_wday: 0,
        tm_yday: 0
    });
}

#[test]
fn asn1time_new() {
    use super::Asn1Time;
    let _ = Asn1Time::from_tm(time::Tm {
        tm_sec: 17, tm_min: 22, tm_hour: 15, tm_mday: 26, tm_mon: 0, tm_year: 116, tm_wday: 2,
        tm_yday: 25, tm_isdst: 0, tm_utcoff: 0, tm_nsec: 94275379
    }).expect("could not create asn1time");
}
