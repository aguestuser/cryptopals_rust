use crate::characters::{CHARACTER_BYTES, FREQS_BY_CHAR, SUMMED_SQUARED_FREQUENCIES};
use crate::encoding::Hex;
use crate::xor_cypher::xor_cycle;
use std::collections::HashMap;

pub fn brute_force_xor_cypher(cyphertext: Hex) -> String {
    let cyphertext_bytes = hex::decode(cyphertext.0).expect("invalid hex");
    let cleartext_bytes = find_min_score_xor(&cyphertext_bytes);
    String::from_utf8(cleartext_bytes.to_vec()).expect("invalid utf-8")
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
    let bytes = xor_cycle(cyphertext_bytes, key);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    lazy_static! {
        static ref GOOD_CANDIDATE: Vec<u8> = {
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
        static ref BAD_CANDIDATE: Vec<u8> = {
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
    fn test_brute_force_xor_cypher() {
        let cleartext = String::from("hello there world how are you.");
        let cyphertext = hex::encode(xor_cycle(&cleartext.as_bytes().to_vec(), &('a' as u8)));
        assert_eq!(brute_force_xor_cypher(Hex(cyphertext)), cleartext);
    }

    #[test]
    fn test_score() {
        assert!((score(&GOOD_CANDIDATE) - 0.016118592).abs() < 0.000000001)
    }

    #[test]
    fn test_score_comparisons() {
        let good_score = score(&GOOD_CANDIDATE);
        let bad_score = score(&BAD_CANDIDATE);
        assert!(good_score < bad_score)
    }

    #[test]
    fn test_sum_frequency_products() {
        assert!((sum_frequency_products(&GOOD_CANDIDATE) - 0.052664608).abs() < 0.000000001);
    }

    #[test]
    fn test_calc_frequencies() {
        let freqs = calc_frequencies(&GOOD_CANDIDATE);
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
}
