use anyhow::{Result, bail};
use strings::{Base64String, HexString};

fn main() {
    set1::chal1();
    set1::chal2();
    set1::chal3();
    set1::chal4();
    set1::chal5();
    set1::chal6();
    set1::chal7();
    set1::chal8();
    set2::chal9();
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
                .filter_map(move |(score, s, _)| if min == score {
                    String::from_utf8(s).ok()
                } else {
                    None
                })
                // Funny enough, there is one more string that has all-valid ASCII,
                // but it is full of newlines and gibberish.
                .any(|s| s.trim() == "Cooking MC's like a pound of bacon")
        );
    }

    pub fn chal4() {
        let file = std::fs::read_to_string("./set1_chal4_input.txt").unwrap();
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

    pub fn chal5() {
        let text = "Burning 'em, if you ain't quick and nimble\n\
                    I go crazy when I hear a cymbal";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let mut bytes = text.as_bytes().to_vec();
        encrypt_with_key(&mut bytes, "ICE".as_bytes());
        let hex = HexString::from_bytes(&bytes);
        assert_eq!(hex.0, expected);
    }

    pub fn chal6() {
        let source = "this is a test";
        let target = "wokka wokka!!!";
        assert_eq!(37, hamming_distance(source.as_bytes(), target.as_bytes()));

        let file = std::fs::read_to_string("set1_chal6.txt").unwrap();
        let base64_str: String = file.lines().collect();
        let bytes = Base64String::new(base64_str).unwrap().to_bytes();

        /*
        let mut normalized_diff_and_keysize: Vec<(u64, u64)> = (2..bytes.len() / 2)
            .map(|keysize| {
                let (a, b) = bytes[..keysize * 2].split_at(keysize);
                let diff = hamming_distance(a, b);
                let keysize: u64 = keysize.try_into().unwrap();
                (diff / keysize, keysize)
            })
            .collect();
        */
        let mut normalized_diff_and_keysize: Vec<(u64, u64, u64)> = (2..bytes.len() / 4)
            .map(|keysize| {
                let bla = &[
                    &bytes[..keysize],
                    &bytes[keysize..keysize * 2],
                    &bytes[keysize * 2..keysize * 3],
                    &bytes[keysize * 3..keysize * 4],
                ];
                let sum_of_all_distances: u64 = bla
                    .iter()
                    .enumerate()
                    .map(|(i, left_slice)| {
                        bla[i..]
                            .iter()
                            .map(|right_slice| hamming_distance(left_slice, right_slice))
                            .sum::<u64>()
                    })
                    .sum();

                let keysize: u64 = keysize.try_into().unwrap();
                (
                    sum_of_all_distances / keysize,
                    sum_of_all_distances % keysize,
                    keysize,
                )
            })
            .collect();
        normalized_diff_and_keysize.sort_unstable();

        // Okay, so the keysize is 29:
        // it is the keysize with smallest diff,
        // and all keysizes with smallest diff after that are just a multiple of 29
        /*
        normalized_diff_and_keysize
            .iter()
            .for_each(|&(diff, modulo, keysize)| {
                println!("keysize: {keysize} diff: {diff}, modulo: {modulo}");
            });
        */
        let keysize: usize = normalized_diff_and_keysize
            .first()
            .unwrap()
            .2
            .try_into()
            .unwrap();

        /*
        try_solve_for_keysize(&bytes, keysize)
            .into_iter()
            .for_each(|(decrypted_str, key)| {
                println!("{decrypted_str}");
                print!("{}", String::from_utf8_lossy_owned(key));
            });
        */
        match try_solve_for_keysize(&bytes, keysize).as_slice() {
            [(text, key)] => {
                assert_eq!(
                    text.trim(),
                    std::fs::read_to_string("set1_chal6_decrypted_text.txt")
                        .unwrap()
                        .trim(),
                );
                assert_eq!(
                    key,
                    std::fs::read_to_string("set1_chal6_key.txt")
                        .unwrap()
                        .as_bytes(),
                );
            }
            _ => unreachable!(),
        }
    }

    pub fn chal7() {
        let key = "YELLOW SUBMARINE";

        let file = std::fs::read_to_string("set1_chal7_input.txt").unwrap();
        let base64 = Base64String::new(file.lines().collect()).unwrap();
        let bytes = base64.to_bytes();

        let decrypted = openssl::symm::decrypt(
            openssl::symm::Cipher::aes_128_ecb(),
            key.as_bytes(),
            None,
            &bytes,
        )
        .unwrap();

        assert_eq!(
            decrypted,
            std::fs::read("set1_chal7_decrypted_text.txt").unwrap()
        );
    }

    pub fn chal8() {
        let file = std::fs::read_to_string("set1_chal8_input.txt").unwrap();
        /*
        file.lines().enumerate().for_each(|(line_idx, line)| {
            use std::{collections::HashSet, ops::Not};

            let hex = HexString::new(line.into()).unwrap();
            let bytes = hex.to_bytes();
            // What am I actually supposed to do with bytes?
            // "
            // Remember that the problem with ECB is that it is stateless and deterministic;
            // the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
            // "
            //
            // Okay, cool, we have 16 byte blocks. And most likely ASCII text.
            // It doesn't necessarily mean it's just rot13 with `13` randomized
            // or something like that, right?
            //
            // There are 10 blocks in every line.
            // I guess I am supposed to search for the blocks that are equal to eachother?
            // Eh, doesn't feel great, but it is better than nothing I guess.
            let (chunks, padding) = bytes.as_chunks::<16>();
            assert_eq!(padding, &[]);

            let mut set: HashSet<&[u8; 16]> = HashSet::new();
            let got_repeat =
                chunks
                    .iter()
                    .enumerate()
                    .fold(false, |got_repeat, (chunk_idx, chunk)| {
                        if set.insert(chunk).not() {
                            let start_in_line = chunk_idx * 32;
                            println!(
                                "16-byte chunk is repeated: {}",
                                &line[start_in_line..start_in_line + 32]
                            );

                            true
                        } else {
                            got_repeat
                        }
                    });

            if got_repeat {
                println!("line {line_idx} appears to be encrypted with ECB; line content:");
                println!("{line}");
            }
        });
        */

        let ecb_string = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(file.lines().nth(132).unwrap(), ecb_string);
        let repeating_chunk = "08649af70dc06f4fd5d2d69c744cd283";
        assert_eq!(&ecb_string[32..64], repeating_chunk);
        assert_eq!(&ecb_string[96..128], repeating_chunk);
        assert_eq!(&ecb_string[160..192], repeating_chunk);
        assert_eq!(&ecb_string[224..256], repeating_chunk);
    }
}

mod set2 {
    use super::*;

    pub fn chal9() {
        // I guess this is gonna be just a bunch of tests for padding function implementation?
        // Sure, whatever.
        assert_eq!(
            pkcs_7(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
        assert_eq!(pkcs_7(b"bla", 4), b"bla\x01");
        assert_eq!(pkcs_7(b"fun", 3), b"fun\x03\x03\x03");
        assert_eq!(
            pkcs_7(b"qwerasdfzxcv1234", 16),
            b"qwerasdfzxcv1234\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        );
    }
}

fn pkcs_7(bytes: &[u8], block_size: u8) -> Vec<u8> {
    let block_size_usize = usize::from(block_size);
    let required_padding = block_size_usize - (bytes.len() % block_size_usize);
    let required_padding =
        u8::try_from(required_padding).expect("`B - (L mod B)` is always at most B");

    let total_len = bytes.len() + usize::from(required_padding);
    let mut padded = Vec::with_capacity(total_len);
    padded.extend_from_slice(bytes);
    padded.extend(std::iter::repeat_n(
        required_padding,
        usize::from(required_padding),
    ));

    padded
}

fn try_solve_for_keysize(bytes: &[u8], keysize: usize) -> Vec<(String, Vec<u8>)> {
    let max_block_len = bytes.len().div_ceil(keysize);
    let transposed_blocks: Vec<Vec<u8>> = (0..keysize)
        .map(|mut idx| {
            let mut vec = Vec::with_capacity(max_block_len);
            while idx < bytes.len() {
                vec.push(bytes[idx]);
                idx += keysize;
            }
            vec
        })
        .collect();

    let mut rebuilt: Vec<u8> = Vec::with_capacity(bytes.len());
    for idx in 0..max_block_len {
        transposed_blocks.iter().for_each(|block| {
            if let Some(x) = block.get(idx) {
                rebuilt.push(*x);
            }
        });
    }
    assert_eq!(bytes.len(), rebuilt.len());
    bytes.iter().zip(rebuilt.iter()).enumerate().for_each(
        |(idx, (original_byte, rebuilt_byte))| {
            assert_eq!(original_byte, rebuilt_byte, "at idx {idx}");
        },
    );

    // get possible answers for every transposed chunk.
    let min_penalty_xor_bytes: Vec<Vec<u8>> = transposed_blocks
        .iter()
        .map(|block| {
            let iter = decrypt_for_every_byte(block);
            let min = iter
                .clone()
                .map(|(penalty_score, _, _)| penalty_score)
                .min()
                .unwrap();
            iter.filter_map(|(penalty_score, _, xor_byte)| {
                if penalty_score == min {
                    Some(xor_byte)
                } else {
                    None
                }
            })
            .collect()
        })
        .collect();

    if min_penalty_xor_bytes.iter().any(Vec::is_empty) {
        return Vec::new();
    }

    // for every possible XOR byte generate a key with other possible XOR bytes.
    let keys: Vec<Vec<u8>> = min_penalty_xor_bytes.into_iter().fold(
        vec![Vec::new()],
        |key_prefixes, sloice_of_xor_bytes| match *sloice_of_xor_bytes.as_slice() {
            [byte] => {
                let mut key_prefixes = key_prefixes;
                key_prefixes.iter_mut().for_each(|prefix| prefix.push(byte));
                key_prefixes
            }
            _ => sloice_of_xor_bytes
                .into_iter()
                .flat_map(|byte| {
                    let mut key_prefixes = key_prefixes.clone();
                    key_prefixes.iter_mut().for_each(|prefix| prefix.push(byte));
                    key_prefixes
                })
                .collect(),
        },
    );

    keys.into_iter()
        .map(|key| {
            let mut bytes = bytes.to_vec();
            decrypt_with_key(&mut bytes, &key);
            let s = String::from_utf8_lossy_owned(bytes);
            (s, key)
        })
        .collect()
}

/// # Panic
///
/// Panics if the slices are not of the same length.
fn hamming_distance(a: &[u8], b: &[u8]) -> u64 {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).fold(0, |differing_bits, (&a, &b)| {
        differing_bits + u64::from((a ^ b).count_ones())
    })
}

fn decrypt_with_key(bytes: &mut [u8], key: &[u8]) {
    bytes
        .iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(encrypted_byte, key_byte)| *encrypted_byte ^= key_byte);
}

fn encrypt_with_key(msg: &mut [u8], key: &[u8]) {
    msg.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(msg_byte, &key_byte)| *msg_byte ^= key_byte);
}

/// Returns `(penalty_score, decrypted_bytes, xor_byte)`
fn decrypt_for_every_byte(bytes: &[u8]) -> impl Iterator<Item = (usize, Vec<u8>, u8)> + Clone {
    (0..=u8::MAX).map(|xor_byte| {
        let mut vec: Vec<u8> = bytes.to_vec();
        vec.iter_mut().for_each(|b| *b ^= xor_byte);

        (penalty_score(&vec), vec, xor_byte)
    })
}

/// Instead of scoring text, score negatively on bad chars.
fn penalty_score(s: &[u8]) -> usize {
    s.len()
        - s.iter()
            //x FIXME: this is kinda bad for general case;
            //x languages other than English get very high penalty
            //x it works for the toy challenge but I'd like a better way for real use cases.
            //x
            //x Maybe it's fine, but use tables per language?
            //x trying to match general utf8 or utf16 is ugly,
            //x although `ascii_whitespace` is probably good at reducing penalty in all languages.
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
        pub fn new(mut s: String) -> Result<Self> {
            while s.ends_with('=') {
                s.pop();
            }

            if s.as_bytes().iter().copied().all(char_is_base64) {
                Ok(Self(s))
            } else {
                bail!("It is not a base64 string: {s}")
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let (chunks, pad) = self.0.as_bytes().as_chunks::<4>();
            let mut vec: Vec<u8> = chunks
                .iter()
                .flat_map(|chunk| {
                    let &[a, b, c, d] = chunk;
                    let (a, b, c, d) = (
                        base64_to_byte(a),
                        base64_to_byte(b),
                        base64_to_byte(c),
                        base64_to_byte(d),
                    );

                    let byte_a = a << 2 | b >> 4;
                    let byte_b = b << 4 | c >> 2;
                    let byte_c = c << 6 | d;
                    [byte_a, byte_b, byte_c].into_iter()
                })
                .collect();
            match *pad {
                [a] => {
                    let a = base64_to_byte(a);
                    let byte_a = a << 2;
                    vec.push(byte_a);
                }
                [a, b] => {
                    let (a, b) = (base64_to_byte(a), base64_to_byte(b));
                    let byte_a = a << 2 | b >> 4;
                    let byte_b = b << 4;
                    vec.push(byte_a);
                    vec.push(byte_b);
                }
                [a, b, c] => {
                    let (a, b, c) = (base64_to_byte(a), base64_to_byte(b), base64_to_byte(c));
                    let byte_a = a << 2 | b >> 4;
                    let byte_b = b << 4 | c >> 2;
                    let byte_c = c << 6;
                    vec.push(byte_a);
                    vec.push(byte_b);
                    vec.push(byte_c);
                }
                _ => (),
            }

            vec
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

    fn base64_to_byte(base64: u8) -> u8 {
        match base64 {
            b'A'..=b'Z' => base64 - b'A',
            b'a'..=b'z' => 26 + base64 - b'a',
            b'0'..=b'9' => 52 + base64 - b'0',
            b'+' => 62,
            b'/' => 63,
            _ => unreachable!("{base64}"),
        }
    }

    fn char_is_base64(cha: u8) -> bool {
        matches!(cha, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
        // matches!(cha, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'=')
    }

    fn map_to_base64(byte: u8) -> u8 {
        match byte {
            0..=25 => byte + b'A',
            26..=51 => byte - 26 + b'a',
            52..=61 => byte - 52 + b'0',
            62 => b'+',
            63 => b'/',
            // to use http-safe base64;
            // 62 => b'-',
            // 63 => b'_',
            _ => unreachable!("{byte}"),
        }
    }
}
