extern crate num_bigint_dig as bigint;
extern crate primal;
extern crate rand;

use bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use bigint::prime;
use num::integer::{lcm, gcd};
use num::traits::{One,Zero};
use rand::rngs::{OsRng};
use rand::{CryptoRng};

pub struct PublicKey {
    pub e:    BigUint,
    pub n:    BigUint,
}

pub struct SecretKey {
    pub d:    BigUint,
    pub n:    BigUint,
    lambda_n: BigUint,
}


fn gen_distinct_primes(keysize: usize) -> (BigUint, BigUint){
    let mut rng = OsRng::new().expect("Failed to build RNG");
    (gen_prime(&mut rng, keysize), gen_prime(&mut rng, keysize))
}

fn gen_prime<T: CryptoRng + RandBigInt>(mut rng: T, keysize: usize) -> BigUint {
    prime::next_prime(&rng.gen_biguint(keysize))
}

fn gen_coprime<'a>(x: &'a BigUint) -> BigUint {
    let mut y = BigUint::new(vec![65_537]);
    loop {
        // TODO: possible to avoid cloning x and y here?
        if gcd(x.clone(),y.clone()).is_one() {
            break y
        } else {
            y = y + BigUint::one();
        }
    }
}


/// Calculates the modular multiplicative inverse *x* of an integer *a*,
/// such that *ax* ≡ 1 (mod *m*), using the extended euclidian algorithm method.
///
/// Modified from: https://github.com/simon-andrews/rust-modinverse
/// See also: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (a_, m_) = (a.to_bigint().unwrap(), m.to_bigint().unwrap());
    let (g, x, _) = egcd(a_, m_.clone());
    if g.is_one() {
       Some((x % m_.clone() + m_.clone()) % m_.clone()).and_then(|bi| bi.to_biguint())
    } else {
       None
    }

}

/// Implements the extended euclidian algorithm.
///
/// Ie: it finds the greatest common denominator of two integers *a* and *b*, and two
/// integers *x* and *y* such that *ax* + *by* is the greatest common
/// denominator of *a* and *b* (Bézout coefficients).
///
/// See: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b, BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(&b % &a, a.clone());
        (g, y - ((b / a) * x.clone()), x.clone())
    }
}

pub fn gen_keypair(keysize: usize) -> (PublicKey, SecretKey) {
    let (p,q) = gen_distinct_primes(keysize);
    let lambda_n = lcm(&p - BigUint::one(), &q - BigUint::one());
    let e = gen_coprime(&lambda_n);
    let d = mod_inverse(&e, &lambda_n).unwrap();
    (
        PublicKey { n: &p * &q, e },
        SecretKey { n: &p * &q, d, lambda_n }
    )
}

pub fn encrypt(m: &BigUint, PublicKey{ e, n }: &PublicKey) -> BigUint {
    m.modpow(&e, &n)
}

pub fn decrypt(c: &BigUint, SecretKey{ d, n, .. }: &SecretKey) -> BigUint {
    c.modpow(&d, &n)
}


/// encodes a byte array as an integer
/// as specified in RFC 8017's OS2IP encoding:
/// https://tools.ietf.org/html/rfc8017#section-4.2
pub fn encode_os2ip(bs: &[u8]) -> BigUint {
    BigUint::from_radix_be(bs, 256).unwrap()
}

/// decodes a byte array from an integer
/// as specified in RFC 8017's I2OSP encoding:
/// https://tools.ietf.org/html/rfc8017#section-4.1
pub fn decode_i2osp(int: BigUint) -> Vec<u8> {
    int.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generating_keypair(){
        let (PublicKey{ e, n: n1 }, SecretKey{ d, n: n2, lambda_n }) = gen_keypair(32);
        assert_eq!(n1, n2);
        assert_eq!((e * d) % lambda_n, BigUint::one());
    }

    #[test]
    fn encrypting_and_decrypting(){
        let (pk, sk) = gen_keypair(32);
        let m = BigUint::new(vec![2]);
        let c = encrypt(&m, &pk);
        assert_eq!(m, decrypt(&c, &sk));
    }

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
    fn generating_coprime(){
        let int = OsRng::new().unwrap().gen_biguint(32);
        let coprime = gen_coprime(&int);
        assert_eq!(gcd(int, coprime), One::one());
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
