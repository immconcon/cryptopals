use anyhow::{Error, Result};

fn main() {
    set1::chal1();
}
mod set1 {
    use super::*;

    pub fn chal1() {
        const SOURCE: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bla = hex_to_base64(SOURCE).unwrap();
        assert_eq!(bla, EXPECTED);
    }
}

fn hex_to_base64(s: &str) -> Result<String> {
    // hex -> 4 bits
    // base64 -> 6 bits
    // 3 hexes -> 2 base64
    // 2 hexes -> byte
    // 3 bytes -> 4 base64
    let (chunks, paddedge) = s.as_bytes().as_chunks::<3>();
    let v: Result<Vec<u8>> =
        chunks
            .iter()
            .try_fold(Vec::new(), |mut res, chunk| -> Result<_, Error> {
                let &[a, b, c] = chunk;
                let (a, b) = three_hex_to_two_base64(a, b, c)?;
                res.push(a);
                res.push(b);
                Ok(res)
            });
    let mut v = v?;
    match paddedge {
        [] => (),
        &[a, b] => {
            let (a, b) = three_hex_to_two_base64(a, b, 0)?;
            v.push(a);
            v.push(b);
            v.push(b'=');
            v.push(b'=');
        }
        [_] => {
            return Err(Error::msg(
                "the hell am I supposed to do with half a byte at the end of the string?",
            ));
        }
        _ => unreachable!(),
    }
    Ok(String::from_utf8(v)?)
}

fn hex_to_byte(hex: u8) -> Result<u8> {
    match hex {
        b'0'..=b'9' => Ok(hex - b'0'),
        b'A'..=b'F' => Ok(hex - b'A' + 10),
        b'a'..=b'f' => Ok(hex - b'a' + 10),
        _ => Err(Error::msg("outside of hex range")),
    }
}

fn byte_to_base64(byte: u8) -> Result<u8> {
    match byte {
        0..=25 => Ok(byte + b'A'),
        26..=51 => Ok(byte - 26 + b'a'),
        52..=61 => Ok(byte - 52 + b'0'),
        // This is http-safe base64;
        // for original use `62 => Ok(b'+'), 63 => Ok(b'/'),`
        62 => Ok(b'-'),
        63 => Ok(b'_'),
        _ => Err(Error::msg("outside of base64 range")),
    }
}

fn three_hex_to_two_base64(a: u8, b: u8, c: u8) -> Result<(u8, u8)> {
    let a = hex_to_byte(a)?;
    let b = hex_to_byte(b)?;
    let c = hex_to_byte(c)?;
    let first = (a << 2) | (b >> 2);
    let second = ((b & 0b11) << 4) | c;

    Ok((byte_to_base64(first)?, byte_to_base64(second)?))
}
