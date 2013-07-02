/*
 * Copyright 2013 Jack Lloyd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{uint,vec};

pub trait ToHex {
    fn to_hex(&self) -> ~str;
}

impl<'self> ToHex for &'self [u8] {
    fn to_hex(&self) -> ~str {

        let chars = "0123456789ABCDEF".iter().collect::<~[char]>();

        let mut s = ~"";

        for uint::range(0, self.len()) |i| {

            let x = self[i];

            let xhi = (x >> 4) & 0x0F;
            let xlo = (x     ) & 0x0F;

            s.push_char(chars[xhi]);
            s.push_char(chars[xlo]);
        }

        s
    }
}

pub trait FromHex {
    fn from_hex(&self) -> ~[u8];
}

impl<'self> FromHex for &'self str {
    fn from_hex(&self) -> ~[u8] {
        let mut vec = vec::with_capacity(self.len() / 2);

        for self.iter().enumerate().advance() |(i,c)| {
            let nibble =
                if c >= '0' && c <= '9' { (c as u8) - 0x30 }
                else if c >= 'a' && c <= 'f' { (c as u8) - (0x61 - 10) }
                else if c >= 'A' && c <= 'F' { (c as u8) - (0x41 - 10) }
                else { fail!(~"bad hex character"); };

            if i % 2 == 0 {
                vec.push(nibble << 4);
            }
            else {
                vec[i/2] |= nibble;
            }
        }

        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test() {

        assert!([05u8, 0xffu8, 0x00u8, 0x59u8].to_hex() == ~"05FF0059");

        assert!("00FFA9D1F5".from_hex() == ~[0, 0xff, 0xa9, 0xd1, 0xf5]);

        assert!("00FFA9D1F5".from_hex().to_hex() == ~"00FFA9D1F5");
    }


}
