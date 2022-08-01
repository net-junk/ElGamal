use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serdesup")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::internal::*;

pub trait ElgamalPublicKeyParts {
    fn get_p(&self) -> &BigUint;
    fn get_q(&self) -> &BigUint;
    fn get_y(&self) -> &BigUint;
    fn get_g(&self) -> &BigUint;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "serdesup",
    derive(Serialize, Deserialize),
    serde(crate = "serde")
)]
pub struct ElgamalPublicKey {
    /// y = g^x
    y: BigUint,
    /// Generator of cyclic group G
    g: BigUint,
    /// Order of cyclic group G
    p: BigUint,
    ///
    q: BigUint,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "serdesup",
    derive(Serialize, Deserialize),
    serde(crate = "serde")
)]
pub struct ElgamalPrivateKey {
    /// Public components of the private key.
    pubkey_components: ElgamalPublicKey,
    /// Private exponent
    pub(crate) x: BigUint,
}

impl ElgamalPublicKeyParts for ElgamalPublicKey {
    fn get_p(&self) -> &BigUint {
        &self.p
    }

    fn get_q(&self) -> &BigUint {
        &self.q
    }

    fn get_g(&self) -> &BigUint {
        &self.g
    }

    fn get_y(&self) -> &BigUint {
        &self.y
    }
}

impl ElgamalPublicKey {
    pub fn new(p: BigUint, q: BigUint, g: BigUint, y: BigUint) -> Self {
        Self { g, p, q, y }
    }
}

impl ElgamalPrivateKey {
    pub fn new(pubkey: ElgamalPublicKey, x: BigUint) -> Self {
        Self {
            pubkey_components: pubkey,
            x,
        }
    }

    /// Returns the private exponent of the key.
    pub fn get_x(&self) -> &BigUint {
        &self.x
    }

    /// Returns the public key.
    pub fn public(&self) -> &ElgamalPublicKey {
        &self.pubkey_components
    }
}

impl ElgamalPublicKeyParts for ElgamalPrivateKey {
    fn get_p(&self) -> &BigUint {
        self.public().get_p()
    }

    fn get_q(&self) -> &BigUint {
        self.public().get_q()
    }

    fn get_g(&self) -> &BigUint {
        self.public().get_g()
    }

    fn get_y(&self) -> &BigUint {
        self.public().get_y()
    }
}

impl From<ElgamalPrivateKey> for ElgamalPublicKey {
    fn from(private_key: ElgamalPrivateKey) -> Self {
        private_key.pubkey_components
    }
}

impl From<&ElgamalPrivateKey> for ElgamalPublicKey {
    fn from(private_key: &ElgamalPrivateKey) -> Self {
        private_key.pubkey_components.clone()
    }
}

impl ElgamalPublicKey {
    /// Encrypt the given message.
    fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        let m = BigUint::from_bytes_be(msg);
        if m.bits() > self.get_p().bits() {
            return Err(Error::MessageTooLong);
        }
        let (a, b) = encrypt(rng, self, &m);

        let mut a = a.to_bytes_be();
        let mut b = b.to_bytes_be();
        a.append(&mut b);

        Ok(a)
    }

    /// Verify a signed message.
    /// `hashed`must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    /// If the message is valid `Ok(())` is returned, otherwiese an `Err` indicating failure.
    fn verify(&self, hashed: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() % 2 != 0 {
            return Err(Error::InvalidData);
        }

        let h = BigUint::from_bytes_be(hashed);
        let (r, s) = sig.split_at(sig.len() / 2);
        let r = BigUint::from_bytes_be(r);
        let s = BigUint::from_bytes_be(s);

        verify(self, &h, &r, &s)
    }
}

impl ElgamalPrivateKey {
    /// Decrypt the given message.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % 2 != 0 {
            return Err(Error::InvalidData);
        }

        let (a, b) = ciphertext.split_at(ciphertext.len() / 2);
        let a = BigUint::from_bytes_be(a);
        let b = BigUint::from_bytes_be(b);

        let m = decrypt(self, &a, &b)?;

        Ok(m.to_bytes_be())
    }

    /// Signe message.
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    fn sign<R: RngCore + CryptoRng>(&self, rng: &mut R, hashed: &[u8]) -> Result<Vec<u8>> {
        let h = BigUint::from_bytes_be(hashed);
        if h.bits() > self.get_p().bits() {
            return Err(Error::MessageTooLong);
        }

        let (r, s) = sign(rng, self, &h)?;

        let mut r = r.to_bytes_be();
        let mut s = s.to_bytes_be();
        r.append(&mut s);

        Ok(s)
    }
}
