extern crate base64;
extern crate hex;

#[derive(Debug, PartialEq)]
pub struct Hex(pub String);

#[derive(Debug, PartialEq)]
pub struct Base64(pub String);

pub fn hex_to_base64(h: Hex) -> Result<Base64, hex::FromHexError> {
    let hex_bytes = hex::decode(h.0)?;
    Ok(Base64(base64::encode(&hex_bytes)))
}

pub fn base64_to_bytes(b: Base64) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode(&b.0)
}

pub fn str2bytes<'a>(s: &'a String) -> &'a [u8] {
    s.as_bytes()
}

pub fn bytes2str(bs: &[u8]) -> String {
    String::from_utf8_lossy(bs).to_string()
}

pub fn bytes2hex(bs: &[u8]) -> Hex {
    Hex(hex::encode(bs))
}

pub fn hex2bytes<'a>(h: &'a Hex) -> Vec<u8> {
    hex::decode(&h.0).expect("invalid hex")
}

#[cfg(test)]
mod tests {
    // use crate::encoding::{hex_to_base64, Base64, Hex};
    use super::*;

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(
            hex_to_base64(Hex(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))),
            Ok(Base64(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))
        );
    }

    #[test]
    fn test_string_to_bytes() {
        assert_eq!(
            str2bytes(&String::from("hello")),
            &[104_u8, 101_u8, 108_u8, 108_u8, 111_u8]
        )
    }

    #[test]
    fn test_bytes_to_string() {
        assert_eq!(
            bytes2str(&[104_u8, 101_u8, 108_u8, 108_u8, 111_u8]),
            String::from("hello")
        );
    }
}
