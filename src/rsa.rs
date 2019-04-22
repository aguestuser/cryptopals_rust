extern crate num;
extern crate primal;
extern crate rand;

use num::bigint::{BigUint, ToBigUint};
use num::traits::{ToPrimitive};
use rand::rngs::OsRng;
use rand::{RngCore};

fn gen_distinct_primes() -> (BigUint, BigUint){
    // TODO: investigate using num_bigint_dig to generate random prime w/ N bits:
    // https://docs.rs/num-bigint-dig/0.4.0/num_bigint_dig

    let base = OsRng::new().expect("Failed to build OS RNG").next_u64();
    let p = (base..).skip_while(|n| !primal::is_prime(*n)).next().unwrap();
    let q = (p..).skip_while(|n| !primal::is_prime(*n)).next().unwrap();

    (p.to_biguint().unwrap(), q.to_biguint().unwrap())
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
    fn generating_keypair(){
        let (p1, q1) = gen_distinct_primes();
        let (p2, q2) = gen_distinct_primes();

        vec![&p1,&q1,&p2,&q2].iter().for_each(|n| assert!(primal::is_prime(n.to_u64().unwrap())));
        assert_ne!(p1, p2);
        assert_ne!(q1, q2);
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
