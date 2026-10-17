use crate::error::{CryptoError, Result};
use crate::hashing::{Hash, DOMAIN_COMMITMENT};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use k256::{ProjectivePoint, AffinePoint};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use std::ops::{Add, Mul};

pub use k256::Scalar;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentKey {
    pub g: AffinePoint,
    pub h: AffinePoint,
}

impl serde::Serialize for CommitmentKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let (g, h) = self.to_bytes();
        use serde::ser::SerializeTuple;
        let mut t = serializer.serialize_tuple(2)?;
        t.serialize_element(&g.as_slice())?;
        t.serialize_element(&h.as_slice())?;
        t.end()
    }
}

impl<'de> serde::Deserialize<'de> for CommitmentKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let (g, h): (Vec<u8>, Vec<u8>) = serde::Deserialize::deserialize(deserializer)?;
        let g_arr: [u8; 33] = g.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid generator length"))?;
        let h_arr: [u8; 33] = h.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid commitment point length"))?;
        Self::from_bytes(&g_arr, &h_arr).map_err(serde::de::Error::custom)
    }
}

impl CommitmentKey {
    pub fn generate() -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let g = ProjectivePoint::GENERATOR.to_affine();
        let mut rng = rand::rngs::OsRng;
        let h_scalar = Scalar::random(&mut rng);
        let h = (ProjectivePoint::GENERATOR * h_scalar).to_affine();
        Self { g, h }
    }

    pub fn from_bytes(g_bytes: &[u8; 33], h_bytes: &[u8; 33]) -> Result<Self> {
        let g = AffinePoint::from_bytes(g_bytes.into())
            .into_option()
            .ok_or_else(|| CryptoError::InvalidParameter("Invalid generator point".into()))?;
        let h = AffinePoint::from_bytes(h_bytes.into())
            .into_option()
            .ok_or_else(|| CryptoError::InvalidParameter("Invalid commitment point".into()))?;
        Ok(Self { g, h })
    }

    pub fn to_bytes(&self) -> ([u8; 33], [u8; 33]) {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let g_bytes: [u8; 33] = self.g.to_encoded_point(true).as_bytes().try_into().expect("33 bytes");
        let h_bytes: [u8; 33] = self.h.to_encoded_point(true).as_bytes().try_into().expect("33 bytes");
        (g_bytes, h_bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct PedersenCommitment {
    pub value: Scalar,
    pub blinding: Scalar,
}

impl PedersenCommitment {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        Self { value, blinding }
    }

    pub fn commit(&self, key: &CommitmentKey) -> Commitment {
        let value_point = key.g * self.value;
        let blinding_point = key.h * self.blinding;
        let commitment_point = (value_point + blinding_point).to_affine();
        Commitment {
            point: commitment_point,
        }
    }

    pub fn verify(&self, key: &CommitmentKey, commitment: &Commitment) -> bool {
        let computed = self.commit(key);
        computed == *commitment
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Commitment {
    pub point: AffinePoint,
}

impl serde::Serialize for Commitment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for Commitment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let arr: [u8; 33] = bytes.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid commitment length"))?;
        Self::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

impl Commitment {
    pub fn to_bytes(&self) -> [u8; 33] {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        self.point.to_encoded_point(true).as_bytes().try_into().expect("33 bytes")
    }

    pub fn from_bytes(bytes: &[u8; 33]) -> Result<Self> {
        let point = AffinePoint::from_bytes(bytes.into())
            .into_option()
            .ok_or_else(|| CryptoError::InvalidParameter("Invalid commitment point".into()))?;
        Ok(Self { point })
    }

    pub fn hash(&self) -> Hash {
        Hash::with_domain(DOMAIN_COMMITMENT, &self.to_bytes())
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct CommitmentOpening {
    pub value: Scalar,
    pub blinding: Scalar,
}

impl CommitmentOpening {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        Self { value, blinding }
    }

    pub fn verify(&self, key: &CommitmentKey, commitment: &Commitment) -> bool {
        let pc = PedersenCommitment::new(self.value, self.blinding);
        pc.verify(key, commitment)
    }
}

pub fn random_scalar() -> Scalar {
    Scalar::random(&mut rand::rngs::OsRng)
}

pub fn random_blinding() -> Scalar {
    random_scalar()
}

#[derive(Clone, Debug, Zeroize)]
pub struct BlindedCommitment {
    pub commitment: Commitment,
    pub blinding: Scalar,
}

impl BlindedCommitment {
    pub fn new(value: Scalar, blinding: Scalar, key: &CommitmentKey) -> Self {
        let pc = PedersenCommitment::new(value, blinding);
        let commitment = pc.commit(key);
        Self { commitment, blinding }
    }

    pub fn unblind(&self, unblinding: &Scalar, key: &CommitmentKey) -> Commitment {
        let unblinded_point = (ProjectivePoint::from(self.commitment.point) - key.h * *unblinding).to_affine();
        Commitment { point: unblinded_point }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_verify() {
        let key = CommitmentKey::generate();
        let value = random_scalar();
        let blinding = random_blinding();
        let pc = PedersenCommitment::new(value, blinding);
        let commitment = pc.commit(&key);
        assert!(pc.verify(&key, &commitment));
    }

    #[test]
    fn test_commitment_binding() {
        let key = CommitmentKey::generate();
        let value1 = random_scalar();
        let value2 = random_scalar();
        let blinding = random_blinding();
        let pc1 = PedersenCommitment::new(value1, blinding);
        let pc2 = PedersenCommitment::new(value2, blinding);
        let c1 = pc1.commit(&key);
        let c2 = pc2.commit(&key);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_blinded_commitment() {
        let key = CommitmentKey::generate();
        let value = random_scalar();
        let blinding = random_blinding();
        let blinded = BlindedCommitment::new(value, blinding, &key);
        let unblinding = random_scalar();
        let unblinded = blinded.unblind(&unblinding, &key);
        assert_ne!(blinded.commitment, unblinded);
    }
}