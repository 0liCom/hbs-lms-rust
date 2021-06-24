use crate::lm_ots::definitions::IType;
use crate::lm_ots::definitions::LmotsAlgorithmType;
use crate::lm_ots::definitions::LmotsPrivateKey;
use crate::lm_ots::definitions::LmotsPublicKey;
use crate::lm_ots::definitions::QType;

use self::definitions::LmotsAlgorithmParameter;
use self::definitions::Seed;

pub mod definitions;
mod keygen;
pub mod signing;
pub mod verify;

pub fn generate_private_key(
    q: QType,
    i: IType,
    seed: Seed,
    parameter: LmotsAlgorithmParameter,
) -> LmotsPrivateKey {
    keygen::generate_private_key(i, q, seed, parameter)
}

pub fn generate_public_key(private_key: &LmotsPrivateKey) -> LmotsPublicKey {
    keygen::generate_public_key(private_key)
}
