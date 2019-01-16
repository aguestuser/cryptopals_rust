extern crate base64;
extern crate hex;

#[derive(Debug, PartialEq)]
pub struct Hex(pub String);

#[derive(Debug, PartialEq)]
pub struct Base64(pub String);

pub fn hex_to_base64(h: Hex) -> Result<Base64, hex::FromHexError> {
    let Hex(hex_str) = h;
    let hex_bytes = hex::decode(hex_str)?;
    Ok(Base64(base64::encode(&hex_bytes)))
}

#[cfg(test)]
mod tests {
    use crate::encoding::{hex_to_base64, Base64, Hex};

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(
        hex_to_base64(Hex(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))),
        Ok(Base64(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))
        );
    }
}
