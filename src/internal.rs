use num_bigint::BigUint;
use num_bigint::ModInverse;
use num_bigint::RandBigInt;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};

use crate::error::{Error, Result};
use crate::keys::{ElgamalPrivateKey, ElgamalPublicKey, ElgamalGroup, ElgamalGroupElements};

use digest::DynDigest;

#[inline]
fn encrypt_raw(
    m: &BigUint,
    p: &BigUint,
    y: &BigUint,
    g: &BigUint,
    r: &BigUint,
) -> (BigUint, BigUint) {
    (g.modpow(r, p), m * y.modpow(r, p))
}

#[inline]
fn decrypt_raw(a: &BigUint, b: &BigUint, p: &BigUint, x: &BigUint) -> Result<BigUint> {
    let mut divider: BigUint = a
        .modpow(x, p)
        .mod_inverse(p)
        .ok_or(Error::InvalidPrivateKey)?
        .to_biguint()
        .unwrap();
    divider *= b;
    divider %= p;

    Ok(divider)
}

#[inline]
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &ElgamalPublicKey,
    m: &BigUint,
) -> (BigUint, BigUint) {
    let r = rng.gen_biguint_range(&BigUint::one(), key.get_q());
    println!("r: {}", r);

    encrypt_raw(m, key.get_p(), key.get_y(), key.get_g(), &r)
}

#[inline]
pub fn reencrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &ElgamalPublicKey,
    a: &BigUint,
    b: &BigUint,
) -> (BigUint, BigUint) {
    let r = rng.gen_biguint_range(&BigUint::one(), key.get_q());

    let (mut a1, b1) = encrypt_raw(b, key.get_p(), key.get_y(), key.get_g(), &r);
    a1 *= a;

    (a1, b1)
}

#[inline]
pub fn decrypt(key: &ElgamalPrivateKey, a: &BigUint, b: &BigUint) -> Result<BigUint> {
    decrypt_raw(a, b, key.get_p(), key.get_x())
}

#[inline]
pub fn verify(
    key: &ElgamalPublicKey,
    h: &BigUint,
    r: &BigUint,
    s: &BigUint,
) -> Result<()> {
    if s > key.get_q() || r > key.get_p() {
        return Err(Error::InvalidRange);
    }

    let p = key.get_p();
    let v1 = key.get_y().modpow(r, p) * r.modpow(s, p) % p;
    let v2 = key.get_g().modpow(h, p);

    match v1 == v2 {
        true => Ok(()),
        false => Err(Error::Verification),
    }
}

#[inline]
pub fn sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &ElgamalPrivateKey,
    h: &BigUint,
) -> Result<(BigUint, BigUint)> {
    let q = key.get_q();
    let k = rng.gen_biguint_range(&BigUint::one(), key.get_q());
    let r = key.get_g().modpow(&k, key.get_p());
    let reverse_k = k
        .mod_inverse(q)
        .ok_or(Error::InvalidInverse)?
        .to_biguint()
        .unwrap();

    let s1 = (key.get_x() * &r) % q;
    let s = match s1 > *h {
        true => (reverse_k * (q + h - s1)) % q,
        false => (reverse_k * (h - s1)) % q,
    };

    Ok((r, s))
}

/// Non-Malleable El Gamal Encryption
#[inline]
pub fn non_malleable_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    digest: &mut dyn DynDigest,
    key: &ElgamalPublicKey,
    m: &BigUint,
) -> (BigUint, BigUint, BigUint, BigUint) {
    let r = rng.gen_biguint_range(&BigUint::one(), key.get_q());
    let s = rng.gen_biguint_range(&BigUint::one(), key.get_q());

    let g = key.get_g();
    let p = key.get_p();
    let q = key.get_q();

    let (a, b) = encrypt_raw(m, p, key.get_y(), g, &r);

    digest.reset();

    let v = g.modpow(&s, p);
    digest.update(&v.to_bytes_be());
    digest.update(&a.to_bytes_be());
    digest.update(&b.to_bytes_be());

    let hash = digest.finalize_reset();
    let c = BigUint::from_bytes_be(hash.as_ref()) % q;
    let d = (&s + &c * &r) % q;

    (a, b, c, d)
}

/// Non-Malleable El Gamal Decryption
#[inline]
pub fn non_malleable_decrypt(
    digest: &mut dyn DynDigest,
    key: &ElgamalPrivateKey,
    a: &BigUint,
    b: &BigUint,
    c: &BigUint,
    d: &BigUint,
) -> Result<BigUint> {
    let g = key.get_g();
    let p = key.get_p();
    let q = key.get_q();

    let a_inverse = a
        .modpow(c, p)
        .mod_inverse(p)
        .ok_or(Error::InvalidPrivateKey)?
        .to_biguint()
        .unwrap();
    let v = g.modpow(d, p) * a_inverse % p;
    digest.reset();
    digest.update(&v.to_bytes_be());
    digest.update(&a.to_bytes_be());
    digest.update(&b.to_bytes_be());

    let hash = digest.finalize_reset();
    let v = BigUint::from_bytes_be(hash.as_ref()) % q;

    println!("v: {}", v);
    println!("c: {}", c);

    if v != *c {
        return Err(Error::Verification);
    }

    decrypt_raw(a, b, p, key.get_x())
}

#[cfg(test)]
mod test {
    use digest::Digest;
    use rand::{prelude::StdRng, SeedableRng};
    use sha2::Sha256;

    use super::*;
    use crate::{
        algorithms::{key_generation, elgamal_parameter_generation_type1},
        keys::{ElgamalPrivateKey, ElgamalPublicKey},
    };

    fn generate_key<R: RngCore + CryptoRng>(
        rng: &mut R,
        l: usize,
        k: usize,
    ) -> (ElgamalPublicKey, ElgamalPrivateKey) {
        let (q,p, g) = elgamal_parameter_generation_type1(rng, l, k);
        let group = ElgamalGroup::new(p,q, g);
        let (y, x) = key_generation(rng, &group);
        let pubkey = ElgamalPublicKey::new(group.clone(), y);
        let privatekey = ElgamalPrivateKey::new(group, x, None);

        (pubkey, privatekey)
    }

    #[test]
    fn encrypt_decrypt() {
        let l = 70;
        let k = 4;
        let mut rng = StdRng::from_entropy();

        let (pub_key, priv_key) = generate_key(&mut rng, l, k);
        let plain_text = rng.gen_biguint_range(&BigUint::one(), pub_key.get_p());

        println!("Pub key: {:?}", pub_key);
        println!("Private key: {:?}", priv_key);
        println!("Plain Text: {}", plain_text);

        let (a, b) = encrypt(&mut rng, &pub_key, &plain_text);

        println!("A: {} , B: {}", a, b);

        let decryprted = decrypt(&priv_key, &a, &b).unwrap();
        println!("decrypted: {}", decryprted);

        assert_eq!(decryprted, plain_text);
    }

    #[test]
    fn non_malleable_encrypt_decrypt() {
        let l = 70;
        let k = 4;
        let mut rng = StdRng::from_entropy();
        let mut digest = Sha256::new();

        let (pub_key, priv_key) = generate_key(&mut rng, l, k);
        let plain_text = rng.gen_biguint_range(&BigUint::one(), pub_key.get_p());

        println!("Pub key: {:?}", pub_key);
        println!("Private key: {:?}", priv_key);
        println!("Plain Text: {}", plain_text);

        let (a, b, c, d) = non_malleable_encrypt(&mut rng, &mut digest, &pub_key, &plain_text);

        println!("A: {} , B: {}, C: {}, D: {}", a, b, c, d);

        let decryprted = non_malleable_decrypt(&mut digest, &priv_key, &a, &b, &c, &d).unwrap();
        println!("decrypted: {}", decryprted);

        assert_eq!(decryprted, plain_text);
    }

    #[test]
    fn sign_verify() {
        let l = 70;
        let k = 4;
        let mut rng = StdRng::from_entropy();

        let (pub_key, priv_key) = generate_key(&mut rng, l, k);
        let plain_text = rng.gen_biguint_range(&BigUint::one(), pub_key.get_p());

        println!("Pub key: {:?}", pub_key);
        println!("Private key: {:?}", priv_key);
        println!("Plain Text: {}", plain_text);
        let (r, s) = sign(&mut rng, &priv_key, &plain_text).unwrap();

        println!("r: {} , s: {}", r, s);

        verify(&pub_key, &plain_text, &r, &s).unwrap();
    }
}
