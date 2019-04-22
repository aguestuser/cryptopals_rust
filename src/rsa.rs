extern crate num_bigint_dig as bigint;
extern crate primal;
extern crate rand;

use bigint::{BigUint, RandBigInt};
use bigint::prime;
use rand::rngs::{OsRng};
use rand::{CryptoRng};

pub fn gen_distinct_primes(keysize: usize) -> (BigUint, BigUint){
    let mut rng = OsRng::new().expect("Failed to build RNG");
    (gen_prime(&mut rng, keysize), gen_prime(&mut rng, keysize))
}

fn gen_prime<T: CryptoRng + RandBigInt>(mut rng: T, keysize: usize) -> BigUint {
    prime::next_prime(&rng.gen_biguint(keysize))
}

/// encodes a byte array as a base 10 integer
/// as specified in RFC 8017's OS2IP encoding
/// see:  https://tools.ietf.org/html/rfc8017#section-4.2
pub fn encode_os2ip(bs: &[u8]) -> BigUint {
    BigUint::from_radix_be(bs, 256).unwrap()
}

/// decodes a byte array from a base 10 integer
/// as specified in RFC 8017's I2OSP encoding
/// see: https://tools.ietf.org/html/rfc8017#section-4.1
pub fn decode_i2osp(int: BigUint) -> Vec<u8> {
    int.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generating_distinct_primes(){
        let (p1, q1) = gen_distinct_primes(32);
        let (p2, q2) = gen_distinct_primes(32);

        vec![&p1,&q1,&p2,&q2].iter().for_each(|n| assert!(prime::probably_prime_lucas(n)));
        assert_ne!(p1, p2);
        assert_ne!(q1, q2);
        assert_ne!(p1, q1);
        assert_ne!(p2, q2);
    }

    #[test]
    fn encoding_byte_array_as_int() {
        assert_eq!(encode_os2ip(&mut [0xFF, 0xFF]), BigUint::new(vec![65535]));
        assert_eq!(encode_os2ip(&mut [0x01, 0x00]), BigUint::new(vec![256]));

        assert_eq!(encode_os2ip(b"xyz"), BigUint::new(vec![7895418]));
        assert_eq!(encode_os2ip(&[120, 121, 122]), BigUint::new(vec![7895418]));
    }

    #[test]
    fn decoding_int_as_bytearray() {
        assert_eq!(decode_i2osp(BigUint::new(vec![65535])), vec![0xFF, 0xFF]);
        assert_eq!(decode_i2osp(BigUint::new(vec![256])), vec![0x01, 0x00]);

        assert_eq!(decode_i2osp(BigUint::new(vec![7895418])), b"xyz");
        assert_eq!(decode_i2osp(BigUint::new(vec![7895418])), &[120, 121, 122]);
    }
}
