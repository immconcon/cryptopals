use anyhow::{Result, bail};
use strings::{Base64String, HexString};

fn main() {
    set1::chal1();
    set1::chal2();
    set1::chal3();
    set1::chal4();
}

mod set1 {
    use super::*;

    pub fn chal1() {
        const SOURCE: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex = HexString::new(SOURCE.into()).unwrap();
        let bytes = hex.to_bytes();
        let base64 = strings::Base64String::from_bytes(&bytes);
        assert_eq!(base64.0, EXPECTED);
    }

    pub fn chal2() {
        let source = "1c0111001f010100061a024b53535009181c";
        let xorge = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let bla = hex_xor(source.into(), xorge.into()).unwrap();
        assert_eq!(bla, expected);
        let back_again = hex_xor(bla, xorge.into()).unwrap();
        assert_eq!(back_again, source);
    }

    pub fn chal3() {
        // Single-byte XOR cipher
        // The hex encoded string:
        let text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        // ... has been XOR'd against a single character. Find the key, decrypt the message.
        //
        // You can do this by hand. But don't: write code to do it for you.
        //
        // How? Devise some method for "scoring" a piece of English plaintext.
        // Character frequency is a good metric.
        // Evaluate each output and choose the one with the best score.
        //
        //
        // Okay, there are 3 ways there could be a message inside.
        // 1. raw bytes from hex form a valid ascii text.
        // 2. base64 string forms a coherent ascii text. Most likely.
        // 3. hex itself contains the message; unlikely, since 6 letters + 10 numbers
        //  will have trouble forming coherent messages, but possible; 1337 is a word after all.
        //
        // Although, the problem doesn't say what is xored and how.
        // I am assuming we are xoring bytes, but what if we are xoring 4-bit parts or 6-bit parts?
        let text_bytes: Vec<u8> = HexString::new(text.into()).unwrap().to_bytes();
        let bla: Vec<_> = decrypt_for_every_byte(&text_bytes).collect();
        let min = bla
            .iter()
            .map(|(score, _, _)| *score)
            .min()
            .expect("`bla` should not be empty");

        assert!(
            bla.into_iter()
                .filter_map(move |(score, s, _)| if min == score { Some(s) } else { None })
                // Funny enough, there is one more string that has all-valid ASCII,
                // but it is full of newlines and gibberish.
                .any(|s| s.trim() == "Cooking MC's like a pound of bacon")
        );
    }

    /// Returns `(inverse_score, decrypted_string, xor_byte)`
    fn decrypt_for_every_byte(bytes: &[u8]) -> impl Iterator<Item = (usize, String, u8)> {
        (0..=u8::MAX).filter_map(|xor_byte| {
            let mut vec: Vec<u8> = bytes.to_vec();
            vec.iter_mut().for_each(|b| *b ^= xor_byte);

            String::from_utf8(vec)
                .ok()
                .map(move |bla| (inverse_score(&bla), bla, xor_byte))
        })
    }

    pub fn chal4() {
        let file = std::fs::read_to_string("./set1_challenge4_input.txt").unwrap();
        let line_len = file.lines().count();
        let valid: Vec<_> = file
            .lines()
            .fold(Vec::with_capacity(line_len * 8), |mut vec, line| {
                let hex = HexString::new(line.into()).unwrap();
                decrypt_for_every_byte(&hex.to_bytes())
                    .map(|(score, s, xor_byte)| (score, s, xor_byte, hex.0.clone()))
                    .for_each(|bla| vec.push(bla));
                vec
            });
        let min = valid.iter().map(|(score, _, _, _)| *score).min().unwrap();

        let min_valid: Vec<_> = valid
            .into_iter()
            .filter_map(|(score, s, xor_byte, original_hex)| {
                if score == min {
                    Some((s, xor_byte, original_hex))
                } else {
                    None
                }
            })
            .collect();
        /*
            .for_each(|(s, xor_byte, original_hex)| {
                println!(
                    "{s}\n\
                    translated by this byte: {xor_byte}\n\
                    original string: {original_hex}"
                )
            });
        */

        assert_eq!(
            min_valid,
            vec![(
                "Now that the party is jumping\n".into(),
                53_u8,
                "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".into(),
            )]
        );
    }
}

/// Instead of scoring text, score negatively on chars other than ascii alphabetic or whitespace.
fn inverse_score(s: &str) -> usize {
    s.len()
        - s.as_bytes()
            .iter()
            .filter(|b| b.is_ascii_alphabetic() || b.is_ascii_whitespace())
            .count()
}

fn hex_xor(a: String, b: String) -> Result<String> {
    if a.len() != b.len() {
        bail!("I don't have a reasonable way to xor hex strings of different length");
    }

    let mut a_bytes = HexString::new(a)?.to_bytes();
    let b_bytes = HexString::new(b)?.to_bytes();

    a_bytes
        .iter_mut()
        .zip(b_bytes.iter())
        .for_each(|(a, &b)| *a ^= b);

    Ok(HexString::from_bytes(&a_bytes).0)
}

mod strings {
    use super::Result;
    use anyhow::bail;

    pub struct HexString(pub String);

    impl HexString {
        pub fn new(s: String) -> Result<Self> {
            if s.len().is_multiple_of(2) && s.as_bytes().iter().copied().all(char_is_hex) {
                Ok(Self(s))
            } else {
                bail!("It is not a hex string: {s}")
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let (chunks, pad) = self.0.as_bytes().as_chunks::<2>();
            assert!(pad.is_empty(), "should be multiple of 2 on creation");
            chunks
                .iter()
                .map(|chunk| {
                    let &[a, b] = chunk;
                    let a = hex_to_byte(a);
                    let b = hex_to_byte(b);
                    a << 4 | b
                })
                .collect()
        }

        pub fn from_bytes(bytes: &[u8]) -> Self {
            let mut vec = Vec::with_capacity(bytes.len() * 2);
            bytes.iter().for_each(|&byte| {
                vec.push(map_to_hex(byte >> 4));
                vec.push(map_to_hex(byte & 0b1111));
            });
            let s = String::from_utf8(vec).expect("hex chars are valid UTF-8");
            Self(s)
        }
    }

    fn hex_to_byte(hex: u8) -> u8 {
        match hex {
            b'0'..=b'9' => hex - b'0',
            b'A'..=b'F' => hex - b'A' + 10,
            // b'a'..=b'f' => hex - b'a' + 10,
            _ => hex - b'a' + 10,
        }
    }

    fn char_is_hex(cha: u8) -> bool {
        cha.is_ascii_hexdigit()
    }

    fn map_to_hex(byte: u8) -> u8 {
        match byte {
            0..=9 => b'0' + byte,
            10..=15 => byte - 10 + b'a',
            _ => unreachable!("{byte}"),
        }
    }

    pub struct Base64String(pub String);

    impl Base64String {
        pub fn new(s: String) -> Result<Self> {
            if s.len().is_multiple_of(4) && s.as_bytes().iter().copied().all(char_is_base64) {
                Ok(Self(s))
            } else {
                bail!("It is not a base64 string: {s}")
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            todo!()
        }

        pub fn from_bytes(bytes: &[u8]) -> Self {
            // base64 -> 6 bits
            // 3 bytes -> 4 base64
            let (chunks, paddedge) = bytes.as_chunks::<3>();
            let mut vec = Vec::with_capacity(bytes.len() * 2);
            chunks.iter().for_each(|chunk| {
                let &[ca, cb, cc] = chunk;
                let a = ca >> 2;
                let b = ((ca & 0b11) << 4) | (cb >> 4);
                let c = ((cb & 0b1111) << 2) | (cc >> 6);
                let d = cc & 0b11_1111;

                vec.push(map_to_base64(a));
                vec.push(map_to_base64(b));
                vec.push(map_to_base64(c));
                vec.push(map_to_base64(d));
            });

            match *paddedge {
                [a] => {
                    vec.push(map_to_base64(a >> 2));
                    vec.push(map_to_base64((a & 0b11) << 4));
                    vec.push(b'=');
                    vec.push(b'=');
                }
                [a, b] => {
                    vec.push(map_to_base64(a >> 2));
                    vec.push(map_to_base64(((a & 0b11) << 4) | (b >> 4)));
                    vec.push(map_to_base64((b & 0b1111) << 2));
                    vec.push(b'=');
                }
                _ => (),
            }

            let s = String::from_utf8(vec).expect("should use unsafe here honestly");
            Self(s)
        }
    }

    fn char_is_base64(cha: u8) -> bool {
        matches!(cha, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'=')
    }

    fn map_to_base64(byte: u8) -> u8 {
        match byte {
            0..=25 => byte + b'A',
            26..=51 => byte - 26 + b'a',
            52..=61 => byte - 52 + b'0',
            // This is http-safe base64;
            // for original use `62 => b'+', 63 => b'/',`
            62 => b'-',
            63 => b'_',
            _ => unreachable!("{byte}"),
        }
    }
}
