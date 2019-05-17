#[macro_use]
extern crate lazy_static;

pub mod characters;
pub mod encoding;
pub mod rsa;
pub mod xor_cypher;
pub mod xor_cypher_attack;

#[cfg(test)]
mod test_set_1 {
    use std::path::{Path};
    use super::xor_cypher;
    use super::encoding;
    use super::xor_cypher_attack;
    use encoding::{Base64, Hex};

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
            xor_cypher::xor_hex(
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
        
        let path = Path::new("data/detect_single_byte_xor.txt");
        let cyphertext = xor_cypher_attack::detect_xor_encryption_from_file(&path);
        assert_eq!(
            xor_cypher_attack::brute_force_xor_cypher(&cyphertext),
            String::from("Now that the party is jumping\n"),
        )
    }

    #[test]
    fn challenge_5(){
        /***
         * Implement repeating-key XOR
         * 
         * Here is the opening stanza of an important work of the English language:
         * 
         * Burning 'em, if you ain't quick and nimble
         * I go crazy when I hear a cymbal
         * 
         * Encrypt it, under the key "ICE", using repeating-key XOR.
         * 
         * In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
         * 
         * It should come out to:
         * 
         * 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
         * a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
         * 
         * Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
         **/

        let cleartext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let key = b"ICE".to_vec();
        let expected_cyphertext = Hex(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));

        assert_eq!(
            xor_cypher::repeating_key_encrypt(&cleartext, &key),
            encoding::hex2bytes(&expected_cyphertext)
        );
        
    }

    #[test]
    fn challenge_6(){
       /************************************
        Break repeating-key XOR
        [...]

        There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

        Decrypt it.

        Here's how:

        (1) Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

        (2) Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

        this is a test

        and

        wokka wokka!!!

        is 37. Make sure your code agrees before you proceed.

        (3) For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

        (4) The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.

        (5) Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

        (6) Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.

        (7) Solve each block as if it was single-character XOR. You already have code to do this.

        (8) For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
         *****/
    }
}
