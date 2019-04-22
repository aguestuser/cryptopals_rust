extern crate num;

use num::bigint::{BigUint, ToBigUint};
use num::pow;
use num::traits::{ToPrimitive, Zero};

/// encodes a byte array as a base 10 integer
/// as specified in RFC 8017's OS2IP encoding
/// see:  https://tools.ietf.org/html/rfc8017#section-4.2
pub fn encode_os2ip(bs: &[u8]) -> BigUint {
    bs.iter()
        .enumerate()
        .fold(Zero::zero(), |acc, (idx, byte)| {
            acc + (byte * pow(BigUint::new(vec![256]), bs.len() - (idx + 1)))
        })
    // equivalent to: BigUint::from_radix_be(bs, 256).unwrap()
}

/// decodes a byte array from a base 10 integer
/// as specified in RFC 8017's I2OSP encoding
/// see: https://tools.ietf.org/html/rfc8017#section-4.1
pub fn decode_i2osp(int: BigUint) -> Vec<u8> {
    if Zero::is_zero(&int) {
        vec![]
    } else {
        let (quotient, remainder) = (
            &int / BigUint::new(vec![256]),
            &int % BigUint::new(vec![256]),
        );
        let mut res = decode_i2osp(quotient);
        res.push(remainder.to_u8().unwrap());
        res
    }
    // equivalent to: int.to_bytes_be()
}

#[cfg(test)]
mod tests {

    use super::*;

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
