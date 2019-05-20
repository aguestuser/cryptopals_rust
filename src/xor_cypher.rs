extern crate hex;
use crate::encoding::Hex;
use hex::FromHexError;

pub fn single_byte_encrypt(bv1: &Vec<u8>, b2: &u8) -> Vec<u8> {
    repeating_key_encrypt(bv1, &vec![*b2])
}

pub fn repeating_key_encrypt(cleartext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    cleartext
        .iter()
        .zip(key.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect::<Vec<_>>()
}

pub fn xor_hex(h1: Hex, h2: Hex) -> Result<Hex, FromHexError> {
    // assert hex strings of equal length
    let (bv1, bv2) = (hex::decode(h1.0)?, hex::decode(h2.0)?);
    let bv3 = xor(&bv1, &bv2);
    Ok(Hex(hex::encode(bv3)))
}

pub fn xor(bs1: &[u8], bs2: &[u8]) -> Vec<u8> {
    bs1.iter()
        .zip(bs2.iter())
        .map(|(&a, &b)| a ^ b)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod xor_cypher_tests {
    use super::*;
    use crate::encoding;
    use encoding::Hex;

    #[test]

    fn test_xor_hex() {
        assert_eq!(
            xor_hex(
                Hex(String::from("1c0111001f010100061a024b53535009181c")),
                Hex(String::from("686974207468652062756c6c277320657965"))
            ),
            Ok(Hex(String::from("746865206b696420646f6e277420706c6179")))
        );
    }

    #[test]
    fn test_xor() {
        assert_eq!(
            xor(&[0b1100_0000, 0b0000_0000], &[0b0110_0000, 0b0000_0000]),
            vec![0b1010_0000, 0b0000_0000]
        );
    }

    #[test]
    fn encrypting_with_single_byte_key() {
        assert_eq!(
            single_byte_encrypt(&vec![0b1100_0000, 0b0000_0000], &0b0110_0000),
            vec![0b1010_0000, 0b0110_0000]
        );
    }

    #[test]
    fn encrypting_with_multiple_byte_key() {
        let cleartext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let key = b"ICE".to_vec();
        let expected_cyphertext = Hex(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));

        assert_eq!(
            repeating_key_encrypt(&cleartext, &key),
            encoding::hex2bytes(&expected_cyphertext)
        );
    }

}
