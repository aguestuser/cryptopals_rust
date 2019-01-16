extern crate hex;
use crate::encoding::Hex;
use hex::FromHexError;

pub fn xor_hex(h1: Hex, h2: Hex) -> Result<Hex, FromHexError> {
    // assert hex strings of equal length
    let (bv1, bv2) = (hex::decode(h1.0)?, hex::decode(h2.0)?);
    let bv3 = xor(bv1, bv2);
    Ok(Hex(hex::encode(bv3)))
}

pub fn xor(bv1: Vec<u8>, bv2: Vec<u8>) -> Vec<u8> {
    bv1.iter()
        .zip(bv2.iter())
        .map(|(&a, &b)| a ^ b)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::encoding::Hex;
    use crate::xor_cypher::{xor, xor_hex};

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
            xor(
                vec![0b1100_0000, 0b0000_0000],
                vec![0b0110_0000, 0b0000_0000]
            ),
            vec![0b1010_0000, 0b0000_0000]
        );
    }
}
