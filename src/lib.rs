pub mod encoding;

#[cfg(test)]
mod tests {
    use super::encoding::{hex_to_base64, Base64, Hex};

    #[test]
    fn challenge_1() {
        assert_eq!(
        hex_to_base64(Hex(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))),
        Ok(Base64(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))
        );
    }
}
