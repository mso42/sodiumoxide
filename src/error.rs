#[cfg(feature = "std")]
use std::error::Error;

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum SodiumError {
    /// The ciphertext should include a prepended MAC, but it was too short.
    CiphertextTooShort,
    /// The ciphertext failed verification.
    CiphertextFailedVerification,
    /// The runtime does not support AES.
    AesUnsupported,
}

pub type Result<T> = core::result::Result<T, SodiumError>;

impl core::fmt::Display for SodiumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use self::SodiumError::*;
        let msg = match self {
            CiphertextTooShort => {
                "The ciphertext should include a prepended MAC, but it was too short."
            }
            CiphertextFailedVerification => "The ciphertext failed verification.",
            AesUnsupported => "The runtime does not support AES",
        };
        write!(f, "{}", msg)
    }
}

#[cfg(feature = "std")]
impl Error for SodiumError {}
