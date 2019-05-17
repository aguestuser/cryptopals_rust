#[macro_use]
extern crate lazy_static;

pub mod characters;
pub mod encoding;
pub mod rsa;
pub mod xor_cypher;
pub mod xor_cypher_attack;

#[cfg(test)]
mod set_1 {
    use std::path::{Path};
    use super::xor_cypher::xor_hex;
    use super::encoding;
    use encoding::{Base64, Hex};
    use super::xor_cypher_attack;


    #[test]
    fn challenge_1() {
        /*
         * Convert hex to base64
         *
         * The string:
         *
         * 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
         *
         * Should produce:
         *
         * SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
         *
         * So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
         */

        assert_eq!(
        encoding::hex_to_base64(Hex(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))),
        Ok(Base64(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))
        );
    }

    #[test]
    fn challenge_2() {
        /************
         * Fixed XOR
         *
         * Write a function that takes two equal-length buffers and produces their XOR combination.
         * If your function works properly, then when you feed it the string:
         *
         * 1c0111001f010100061a024b53535009181c
         *
         * ... after hex decoding, and when XOR'd against:
         *
         * 686974207468652062756c6c277320657965
         *
         * ... should produce:
         *
         * `746865206b696420646f6e277420706c6179
         *
         **/

        assert_eq!(
            xor_hex(
                Hex(String::from("1c0111001f010100061a024b53535009181c")),
                Hex(String::from("686974207468652062756c6c277320657965"))
            ),
            Ok(Hex(String::from("746865206b696420646f6e277420706c6179")))
        );
    }

    #[test]
    fn challenge_3() {
        /***
         * Single-byte XOR cipher
         *
         * The hex encoded string:
         *
         * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
         *
         * ... has been XOR'd against a single character. Find the key, decrypt the message.
         * You can do this by hand. But don't: write code to do it for you.
         * How? Devise some method for "scoring" a piece of English plaintext.
         * Character frequency is a good metric. Evaluate each output and choose the one with the best score.
         **/

        let cyphertext = encoding::hex2bytes(&Hex(String::from(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )));
        assert_eq!(
            xor_cypher_attack::brute_force_xor_cypher(&cyphertext),
            String::from("Cooking MC's like a pound of bacon")
        )
    }

    #[test]
    fn challenge_4() {

        /***
         * One of the 60-character strings in this file [./data/detect_single_byte_xor.txt] has been encrypted by single-character XOR.
         * Find it.
         **/
        
        let path = Path::new("src/data/detect_single_byte_xor.txt");
        let cyphertext = xor_cypher_attack::detect_xor_encryption_from_file(&path);
        assert_eq!(
            xor_cypher_attack::brute_force_xor_cypher(&cyphertext),
            String::from("Now that the party is jumping\n"),
        )
    }
}
