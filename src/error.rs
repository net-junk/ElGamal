pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidPrivateKey,
    MessageTooLong,
    Verification,
    InvalidInverse,
    InvalidRange,
    InvalidData,
    InvalidOID,
    PrivateKeyMalformed,
    PublicKeyMalformed,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::InvalidPrivateKey => write!(f, "invalid PrivateKey"),
            Error::Verification => write!(f, "verification error"),
            Error::InvalidInverse => write!(f, "failed ot find inverse"),
            Error::InvalidRange => write!(f, "integer not in range"),
            Error::MessageTooLong => write!(f, "message too long"),
            Error::InvalidData => write!(f, "invalid data"),
            Error::InvalidOID => write!(f, "invalid OID"),
            Error::PrivateKeyMalformed => write!(f, "private key is malformed"),
            Error::PublicKeyMalformed => write!(f, "public key is malformed"),
        }
    }
}
