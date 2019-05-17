use crate::characters::{CHARACTER_BYTES, FREQS_BY_CHAR, SUMMED_SQUARED_FREQUENCIES};
use crate::encoding;
use crate::xor_cypher;
use encoding::Hex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

/********************
 * BRUTE FORCE XOR
 ********************/

/// brute force single byte xor encryption by guessing every possible byte
/// as a potential key, and keeping the guess whose character frequency
/// distribution most closely matches the ground truth distribution
/// observed in English text
pub fn brute_force_xor_cypher_from_hex(cyphertext: &Hex) -> String {
    let cyphertext_bytes = encoding::hex2bytes(&cyphertext);
    let cleartext_bytes = find_min_score_xor(&cyphertext_bytes);
    String::from_utf8_lossy(&cleartext_bytes).to_string()
}

pub fn brute_force_xor_cypher(cyphertext_bytes: &Vec<u8>) -> String {
    let cleartext_bytes = find_min_score_xor(cyphertext_bytes);
    String::from_utf8_lossy(&cleartext_bytes).to_string()
}

fn find_min_score_xor(cyphertext_bytes: &Vec<u8>) -> Vec<u8> {
    CHARACTER_BYTES
        .iter()
        .fold((Vec::<u8>::new(), std::f64::MAX), |curr_guess, key| {
            let new_guess = evaluate_guess(cyphertext_bytes, key);
            if new_guess.1 < curr_guess.1 {
                new_guess
            } else {
                curr_guess
            }
        })
        .0
}

fn evaluate_guess(cyphertext_bytes: &Vec<u8>, key: &u8) -> (Vec<u8>, f64) {
    let bytes = xor_cypher::single_byte_encrypt(cyphertext_bytes, key);
    let score = score(&bytes);
    (bytes, score)
}

/// measure the deviation of the observed distribution of character bytes
/// with the ground truth distribution by finding the difference between:
/// (1) the summed squared frequencies of ground truth distribution
/// (2) the summed product of observed and ground truth frequencies
/// if the observed frequency distribution conforms perfectly to ground truth,
/// the difference will be 0
/// (cf: Katz & Lindell's *Introduction To Modern Cryptography*, p. 12)
fn score(cyphertext_bytes: &Vec<u8>) -> f64 {
    (sum_frequency_products(cyphertext_bytes) - SUMMED_SQUARED_FREQUENCIES).abs()
}

/// measure the distribution of english characters
/// in a given byte array by summing the product of:
/// (1) the observed frequency of the ith character in the observed array
/// (2) the ground-truth frequency of the ith character in the observed array
/// for every byte in the array
fn sum_frequency_products(bytes: &Vec<u8>) -> f64 {
    let observed_freqs: HashMap<u8, f64> = calc_frequencies(bytes);
    FREQS_BY_CHAR.iter().fold(0_f64, |acc, (b, freq)| {
        acc + (freq * observed_freqs.get(&b).unwrap_or(&0_f64))
    })
}

fn calc_frequencies(bytes: &Vec<u8>) -> HashMap<u8, f64> {
    let len = bytes.len() as f64;
    let mut counts = HashMap::<u8, usize>::new();
    for &b in bytes.iter() {
        let count = counts.entry(b).or_insert(0);
        *count += 1;
    }
    counts
        .iter()
        .map(|(&k, v)| (k, (*v as f64 / len)))
        .collect::<HashMap<u8, f64>>()
}

/*************************
 * DETECT XOR ENCRYPTION
 *************************/

/// read possibly encrypted messages from file, then detect which one
/// is most likely to be single-byte xor encrypted based on entropy
pub fn detect_xor_encryption_from_file(path: &Path) -> Vec<u8> {
    let f = File::open(path).expect("failed to open file");
    let messages = BufReader::new(&f)
        .lines()
        .map(|l| encoding::hex2bytes(&encoding::Hex(l.expect("could not read line"))))
        .collect::<Vec<Vec<u8>>>();
    detect_xor_encryption(messages)
}

/// detect message with lowest entropy, where we use a high number of missing bytes
/// as a proxy for narrow/clumped distribution of bytes & :. low entropy
pub fn detect_xor_encryption(messages: Vec<Vec<u8>>) -> Vec<u8> {
    messages[1..]
        .iter()
        .fold(
            (&messages[0], count_missing_bytes(&messages[0])),
            |(curr_guess, curr_max), msg| match count_missing_bytes(msg) {
                new_max if new_max > curr_max => (msg, new_max),
                _ => (curr_guess, curr_max),
            },
        )
        .0
        .to_vec()
}

/// count the number of byte values (ints between 0 and 255) not present in an input byte array
fn count_missing_bytes(message: &[u8]) -> usize {
    let present_bytes = message.iter().collect::<HashSet<&u8>>();
    256 - present_bytes.len()
}

#[cfg(test)]
mod xor_attack_tests {
    use super::*;
    use crate::encoding;
    use std::iter;

    lazy_static! {
        static ref ENGLISH_LIKE_DISTR: Vec<u8> = {
            iter::repeat('a')
                .take(8)
                .chain(iter::repeat('e').take(7))
                .chain(iter::repeat('i').take(5))
                .chain(iter::repeat('o').take(5))
                .chain(iter::repeat('r').take(5))
                .chain(iter::repeat('s').take(4))
                .chain(iter::repeat('n').take(4))
                .chain(iter::repeat('1').take(4))
                .chain(iter::repeat('2').take(3))
                .chain(iter::repeat('t').take(3))
                .chain(iter::repeat('u').take(2))
                .collect::<String>()
                .as_bytes()
                .to_vec()
        };
        static ref NON_ENGLISH_LIKE_DISTR: Vec<u8> = {
            iter::repeat('&')
                .take(8)
                .chain(iter::repeat(':').take(7))
                .chain(iter::repeat('|').take(5))
                .chain(iter::repeat('>').take(5))
                .chain(iter::repeat('<').take(5))
                .chain(iter::repeat(';').take(4))
                .chain(iter::repeat('?').take(4))
                .chain(iter::repeat('ö').take(4))
                .chain(iter::repeat('{').take(3))
                .chain(iter::repeat('}').take(3))
                .chain(iter::repeat('=').take(2))
                .collect::<String>()
                .as_bytes()
                .to_vec()
        };
    }

    #[test]
    fn counting_missing_bytes() {
        let bs1: &[u8] = &(0u8..=255u8).into_iter().collect::<Vec<u8>>()[..];
        let bs2: &[u8] = &(0u8..=127u8).into_iter().collect::<Vec<u8>>()[..];
        let bs3: &[u8] = &(0u8..=0u8).into_iter().collect::<Vec<u8>>()[..];

        assert_eq!(count_missing_bytes(bs1), 0);
        assert_eq!(count_missing_bytes(bs2), 128);
        assert_eq!(count_missing_bytes(bs3), 255);
    }

    #[test]
    fn test_brute_force_xor_cypher() {
        let cleartext = String::from("hello there world how are you.");
        let cyphertext =
            xor_cypher::single_byte_encrypt(&cleartext.as_bytes().to_vec(), &('a' as u8));
        assert_eq!(brute_force_xor_cypher(&cyphertext), cleartext);
    }

    #[test]
    fn test_score() {
        assert!((score(&ENGLISH_LIKE_DISTR) - 0.016118592).abs() < 0.000000001)
    }

    #[test]
    fn test_score_comparisons() {
        let good_score = score(&ENGLISH_LIKE_DISTR);
        let bad_score = score(&NON_ENGLISH_LIKE_DISTR);
        assert!(good_score < bad_score)
    }

    #[test]
    fn test_sum_frequency_products() {
        assert!((sum_frequency_products(&ENGLISH_LIKE_DISTR) - 0.052664608).abs() < 0.000000001);
    }

    #[test]
    fn test_calc_frequencies() {
        let freqs = calc_frequencies(&ENGLISH_LIKE_DISTR);
        assert_eq!(freqs.get(&('a' as u8)), Some(&0.16));
        assert_eq!(freqs.get(&('e' as u8)), Some(&0.14));
        assert_eq!(freqs.get(&('i' as u8)), Some(&0.10));
        assert_eq!(freqs.get(&('o' as u8)), Some(&0.10));
        assert_eq!(freqs.get(&('r' as u8)), Some(&0.10));
        assert_eq!(freqs.get(&('s' as u8)), Some(&0.08));
        assert_eq!(freqs.get(&('n' as u8)), Some(&0.08));
        assert_eq!(freqs.get(&('1' as u8)), Some(&0.08));
        assert_eq!(freqs.get(&('2' as u8)), Some(&0.06));
        assert_eq!(freqs.get(&('t' as u8)), Some(&0.06));
        assert_eq!(freqs.get(&('u' as u8)), Some(&0.04));
    }

    #[test]
    fn detecting_xor_encryption() {
        let possibly_encrypted_messages = vec![
            Hex("33e80130f45708395457573406422a3b0d03e6e5053d0d2d151c083337a2".to_string()),
            Hex("551be2082b1563c4ec2247140400124d4b6508041b5a472256093aea1847".to_string()),
            Hex("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".to_string()),
            Hex("0864eb4935144c501103a71851370719301bec57093a0929ea3f18060e55".to_string()),
            Hex("2d395e57143359e80efffb13330633ea19e323077b4814571e5a3de73a1f".to_string()),
        ]
        .iter()
        .map(|hex| encoding::hex2bytes(&hex))
        .collect::<Vec<Vec<u8>>>();

        assert_eq!(
            detect_xor_encryption(possibly_encrypted_messages.clone()),
            possibly_encrypted_messages[2],
        )
    }

    #[test]
    fn detecting_xor_encryption_from_file() {
        let path = Path::new("data/single_byte_xor_small_sample.txt");
        assert_eq!(
            detect_xor_encryption_from_file(&path),
            encoding::hex2bytes(&Hex(
                "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".to_string()
            )),
        )
    }
}
