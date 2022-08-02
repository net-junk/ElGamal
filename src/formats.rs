

use der::{
    asn1::{AnyRef, BitString, ObjectIdentifier, UIntRef},
    Decode, DecodeValue, Encode, Header, Reader, Sequence, SliceReader,
};
use num_bigint::BigUint;
use num_traits::One;

use crate::{ElgamalPrivateKey, ElgamalPublicKey, ElgamalGroup, keys::ElgamalGroupElements};
use crate::error::{Error, Result};


const ELGAMAL_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.7.2.1.1");
const DSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

fn verify_algorithm_id(oid: &ObjectIdentifier) -> bool
{
    if *oid == ELGAMAL_OID || *oid == DSA_OID
    {
        return true;
    }
    return false;
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GroupParams<'a> {
    ///
    pub p: UIntRef<'a>,
    ///
    pub q: Option<UIntRef<'a>>,
    ///
    pub g: UIntRef<'a>,
}

/// X.509 `AlgorithmIdentifier`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct KeyInfo<'a> {
    /// Object Identifier
    pub algorithm: ObjectIdentifier,
    /// Paramaters ofr Group
    pub group_params: GroupParams<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PublicKeyInfo<'a> {
    pub info: KeyInfo<'a>,
    #[asn1(type = "BIT STRING")]
    pub y: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PrivateKeyInfo<'a> {
    pub version: u8,
    pub info: KeyInfo<'a>,
    #[asn1(type = "OCTET STRING")]
    pub x: &'a [u8],
}

impl TryFrom<PrivateKeyInfo<'_>> for ElgamalPrivateKey {
    type Error = Error;

    fn try_from(private_key_info: PrivateKeyInfo<'_>) -> Result<Self> {
        if !verify_algorithm_id(&private_key_info.info.algorithm)
        {
            return  Err(Error::InvalidOID);
        }

        if private_key_info.version != 0
        {
            return  Err(Error::PrivateKeyMalformed);
        }

        let p = BigUint::from_bytes_be(private_key_info.info.group_params.p.as_bytes());
        let g = BigUint::from_bytes_be(private_key_info.info.group_params.g.as_bytes());
        let q = match private_key_info.info.group_params.q 
        {
            None => {
                (&p - BigUint::one()) << 1
            },
            Some(ref q) => {
                BigUint::from_bytes_be(q.as_bytes())
            }
        };


        let x = BigUint::from_bytes_be(private_key_info.x);
        Ok(ElgamalPrivateKey::new(ElgamalGroup::new(p, q, g), x, None))
    }
}


impl TryFrom<PublicKeyInfo<'_>> for ElgamalPublicKey {
    type Error = Error;

    fn try_from(public_key_info: PublicKeyInfo<'_>) -> Result<Self> {
        if !verify_algorithm_id(&public_key_info.info.algorithm)
        {
            return  Err(Error::InvalidOID);
        }


        let p = BigUint::from_bytes_be(public_key_info.info.group_params.p.as_bytes());
        let g = BigUint::from_bytes_be(public_key_info.info.group_params.g.as_bytes());
        let q = match public_key_info.info.group_params.q 
        {
            None => {
                (&p - BigUint::one()) << 1
            },
            Some(ref q) => {
                BigUint::from_bytes_be(q.as_bytes())
            }
        };


        let y = BigUint::from_bytes_be(public_key_info.y);
        Ok(ElgamalPublicKey::new(ElgamalGroup::new(p, q, g), y))
    }
}


pub fn public_key_encode(public_key: &ElgamalPublicKey) -> Result<Vec<u8>> {


        let p = public_key.get_p().to_bytes_be();
        let g = public_key.get_g().to_bytes_be();
        let q = public_key.get_q().to_bytes_be();
        let y = public_key.get_y().to_bytes_be();
        
        let info = PublicKeyInfo
        {
            info: KeyInfo {
                algorithm: ELGAMAL_OID,
                group_params: GroupParams { p: UIntRef::new(&p).map_err(|_| Error::InvalidData)?, 
                    q: Some(UIntRef::new(&q).map_err(|_| Error::InvalidData)?), g: UIntRef::new(&g).map_err(|_| Error::InvalidData)?}
            },
            y: &y
        };
        
        let mut data = Vec::new();
        let _len = info.encode_to_vec(&mut data).map_err(|_| Error::InvalidData)?;

        Ok(data)
}

pub fn private_key_encode(private_key: &ElgamalPrivateKey) -> Result<Vec<u8>> {


    let p = private_key.get_p().to_bytes_be();
    let g = private_key.get_g().to_bytes_be();
    let q = private_key.get_q().to_bytes_be();
    let x = private_key.get_x().to_bytes_be();
    
    let info = PrivateKeyInfo
    {
        version: 0, 
        info: KeyInfo {
            algorithm: ELGAMAL_OID,
            group_params: GroupParams { p: UIntRef::new(&p).map_err(|_| Error::InvalidData)?, 
                q: Some(UIntRef::new(&q).map_err(|_| Error::InvalidData)?), g: UIntRef::new(&g).map_err(|_| Error::InvalidData)?}
        },
        x: &x
    };
    
    let mut data = Vec::new();
    let _len = info.encode_to_vec(&mut data).map_err(|_| Error::InvalidData)?;

    Ok(data)
}

#[cfg(test)]
mod test {
    use std::io::Read;

    use rand::{prelude::StdRng, SeedableRng};

    use crate::{keys::elgamal_key_generate};

    use super::*;

    #[test]
    fn read_der_files() {
        let mut file = std::fs::File::open("tests/pub.der").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let key = PublicKeyInfo::from_der(data.as_ref()).unwrap();

        let mut file = std::fs::File::open("tests/priv.der").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let key = PrivateKeyInfo::from_der(data.as_ref()).unwrap();
    }

    #[test]
    fn der_keys()
    {
        let mut rng = StdRng::from_entropy();
        let group = ElgamalGroup::generate(&mut rng, 1024, 1000);
        let (pub_key, priv_key) = elgamal_key_generate(&mut rng, &group);
        
        let pub_raw = public_key_encode(&pub_key).unwrap();
        let _key = PublicKeyInfo::from_der(pub_raw.as_ref()).unwrap();

        let priv_key = private_key_encode(&priv_key).unwrap();
        let _key = PrivateKeyInfo::from_der(priv_key.as_ref()).unwrap();
    }
}
