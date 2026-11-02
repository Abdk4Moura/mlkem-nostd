//! ML-KEM (FIPS 203) parameter sets.
//!
//! The three NIST parameter sets are zero-sized types. All sizes are derived
//! from `k`, `eta1`, `du` and `dv`, so the same code is instantiated for each
//! set without runtime branching on the parameter set.

/// One of the three ML-KEM parameter sets defined in FIPS 203 Section 8.
///
/// Implementors are zero-sized marker types. The associated constants are
/// public parameters, never secret data.
pub trait ParameterSet: Copy + Clone + Send + Sync + 'static {
    /// Module rank `k`.
    const K: usize;
    /// CBD parameter used for the secret vector `s` and the encryption
    /// randomness `y`.
    const ETA1: usize;
    /// CBD parameter used for the error vectors `e`, `e1`, `e2` and `e2`.
    const ETA2: usize;
    /// Number of bits per coefficient of `u` in the ciphertext.
    const DU: usize;
    /// Number of bits per coefficient of `v` in the ciphertext.
    const DV: usize;

    /// Encapsulation key size in bytes: `384*k + 32`.
    const EK_BYTES: usize = 384 * Self::K + 32;
    /// Decapsulation key size in bytes: `768*k + 96`.
    const DK_BYTES: usize = 768 * Self::K + 96;
    /// Ciphertext size in bytes: `32*(du*k + dv)`.
    const CT_BYTES: usize = 32 * (Self::DU * Self::K + Self::DV);
    /// `k*384`, the size of the K-PKE decryption key.
    const DK_PKE_BYTES: usize = 384 * Self::K;

    /// Human-readable FIPS 203 name.
    const NAME: &'static str;
}

/// ML-KEM-512, NIST security category 1 (`k = 2`, `eta1 = 3`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem512;

/// ML-KEM-768, NIST security category 3 (`k = 3`, `eta1 = 2`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem768;

/// ML-KEM-1024, NIST security category 5 (`k = 4`, `eta1 = 2`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem1024;

impl ParameterSet for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-512";
}

impl ParameterSet for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-768";
}

impl ParameterSet for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const NAME: &'static str = "ML-KEM-1024";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_203_sizes() {
        assert_eq!(MlKem512::EK_BYTES, 800);
        assert_eq!(MlKem512::DK_BYTES, 1632);
        assert_eq!(MlKem512::CT_BYTES, 768);

        assert_eq!(MlKem768::EK_BYTES, 1184);
        assert_eq!(MlKem768::DK_BYTES, 2400);
        assert_eq!(MlKem768::CT_BYTES, 1088);

        assert_eq!(MlKem1024::EK_BYTES, 1568);
        assert_eq!(MlKem1024::DK_BYTES, 3168);
        assert_eq!(MlKem1024::CT_BYTES, 1568);
    }

    #[test]
    fn fips_203_parameters() {
        assert_eq!(
            (MlKem512::K, MlKem512::ETA1, MlKem512::DU, MlKem512::DV),
            (2, 3, 10, 4)
        );
        assert_eq!(
            (MlKem768::K, MlKem768::ETA1, MlKem768::DU, MlKem768::DV),
            (3, 2, 10, 4)
        );
        assert_eq!(
            (MlKem1024::K, MlKem1024::ETA1, MlKem1024::DU, MlKem1024::DV),
            (4, 2, 11, 5)
        );
    }
}
