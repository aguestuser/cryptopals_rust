use crate::xor_cypher;

///
/// measures number of differing bits in two byte arrays by:
///
/// (1) xoring byte arrays
/// (2) counting number of set bits in xored byte array
///
/// this works because xored byte array will have set bits in all positions
/// in which input byte arrays had differing bits)
///
fn measure_hamming_distance(bs1: &[u8], bs2: &[u8]) -> u32 {
    xor_cypher::xor(bs1, bs2)
        .iter()
        .fold(0, |acc, byte| acc + byte.count_ones())
}

#[cfg(test)]
mod xor_attack_repeating_tests {
    use super::*;

    #[test]
    fn measuring_hamming_distance() {
        let txt1 = &b"this is a test"[..];
        let txt2 = &b"wokka wokka!!!"[..];

        assert_eq!(measure_hamming_distance(txt1, txt2), 37)
    }
}
