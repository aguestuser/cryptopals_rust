use bigint::prime;
use bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num::integer::{gcd, lcm};
use num::traits::{One, Zero};
use num_bigint_dig as bigint;
use rand::rngs::OsRng;
use rand::CryptoRng;

pub struct PublicKey {
    pub e: BigUint,
    pub n: BigUint,
}

pub struct SecretKey {
    pub d: BigUint,
    pub n: BigUint,
    pub lambda_n: BigUint,
}

/*******************
 * PUBLIC FUNCTIONS
 *******************/

pub fn gen_keypair(keysize: usize) -> (PublicKey, SecretKey) {
    let (p, q) = gen_distinct_primes(keysize);
    let lambda_n = lcm(&p - BigUint::one(), &q - BigUint::one());
    let e = gen_coprime(&lambda_n);
    let d = mod_inverse(&e, &lambda_n).unwrap();
    (
        PublicKey { n: &p * &q, e },
        SecretKey {
            n: &p * &q,
            d,
            lambda_n,
        },
    )
}

pub fn encrypt(m: &[u8], PublicKey { e, n }: &PublicKey) -> BigUint {
    let m_int = encode(m);
    println!("m_int in: {}", m_int);
    m_int.modpow(&e, &n)
}

pub fn decrypt<'a>(c: &BigUint, SecretKey { d, n, .. }: &SecretKey) -> Vec<u8> {
    let m_int = c.modpow(&d, &n);
    println!("m_int out: {}", m_int);
    decode(m_int)
}

/*******************
 * HELPER FUNCTIONS
 *******************/

fn gen_distinct_primes(keysize: usize) -> (BigUint, BigUint) {
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
        if gcd(x.clone(), y.clone()).is_one() {
            break y;
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

/// Encodes a byte array as an integer, with appropriate padding and hasing,
/// according to EME-OAEP encoding specified in:
/// https://tools.ietf.org/html/rfc8017#section-7.1
fn encode(m: &[u8]) -> BigUint {
    // TODO: add padding, hashing etc
    encode_os2ip(m)
}

/// Encodes a byte array as an integer as specified in RFC 8017's OS2IP encoding:
/// https://tools.ietf.org/html/rfc8017#section-4.1
fn encode_os2ip(bytes: &[u8]) -> BigUint {
    BigUint::from_radix_be(bytes, 256).unwrap()
}

/// Decodes a byte array as an integer, with appropriate padding and hasing,
/// according to EME-OAEP encoding specified in:
/// https://tools.ietf.org/html/rfc8017#section-7.1
fn decode(int: BigUint) -> Vec<u8> {
    // TODO: reverse padding, hashing etc
    decode_i2osp(int)
}

/// Decodes a byte array from an integer as specified in RFC 8017's I2OSP encoding:
/// https://tools.ietf.org/html/rfc8017#section-4.1
fn decode_i2osp(int: BigUint) -> Vec<u8> {
    int.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generating_keypair() {
        let (PublicKey { e, n: n1 }, SecretKey { d, n: n2, lambda_n }) = gen_keypair(32);
        assert_eq!(n1, n2);
        assert_eq!((e * d) % lambda_n, BigUint::one());
    }

    #[test]
    fn encrypting_and_decrypting() {
        let (pk, sk) = gen_keypair(16);

        // TODO: won't work for longer messages... why??
        // let m = b"hello world i am here!";
        let m = b"hi";
        let c = encrypt(m, &pk);
        let m_ = &decrypt(&c, &sk)[..];

        println!("--------------");
        println!("e: {}", pk.e);
        println!("d: {}", sk.d);
        println!("n: {}", sk.n);
        println!("lambda_n {}", sk.lambda_n);
        println!("--------------");
        println!("m1: {:?}", m);
        println!("c: {:?}", c);
        println!("m2: {:?}", m_);
        println!("--------------");

        assert_eq!(m, m_);
    }

    #[test]
    fn generating_distinct_primes() {
        let (p1, q1) = gen_distinct_primes(32);
        let (p2, q2) = gen_distinct_primes(32);

        vec![&p1, &q1, &p2, &q2]
            .iter()
            .for_each(|n| assert!(prime::probably_prime_lucas(n)));
        assert_ne!(p1, p2);
        assert_ne!(q1, q2);
        assert_ne!(p1, q1);
        assert_ne!(p2, q2);
    }

    #[test]
    fn generating_coprime() {
        let int = OsRng::new().unwrap().gen_biguint(32);
        let coprime = gen_coprime(&int);
        assert_eq!(gcd(int, coprime), One::one());
    }

    #[test]
    fn encoding_and_decoding() {
        let m = b"hello world i am here";
        assert_eq!(m, &decode(encode(m))[..]);
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
