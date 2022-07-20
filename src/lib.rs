//#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! This library implements the Leighton-Micali-Signature scheme, as defined in the
//! [RFC 8554](<https://datatracker.ietf.org/doc/html/rfc8554>).
//!
//! It is a post-quantum secure algorithm that can be used to
//! generate digital signatures. NIST has published recommendations for this algorithm in:
//! [NIST Recommendations for Stateful Hash-Based Signatures](https://doi.org/10.6028/NIST.SP.800-208)
//!
//! This crate can be used together with the [`signature::SignerMut`] and [`signature::Verifier`] traits.
//!
//! # Example
//! ```
//! use rand::{rngs::OsRng, RngCore};
//! use tinyvec::ArrayVec;
//! use hbs_lms::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm,
//!     Signature, signature::{SignerMut, Verifier},
//!     Sha256_256, HashChain, Seed,
//! };
//!
//! let message: [u8; 7] = [42, 84, 34, 12, 64, 34, 32];
//!
//! // Generate keys for a 2-level HSS system (RootTree W1/H5, ChildTree W2/H5)
//! let hss_parameter = [
//!         HssParameter::<Sha256_256>::new(LmotsAlgorithm::LmotsW1, LmsAlgorithm::LmsH5),
//!         HssParameter::<Sha256_256>::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
//! ];
//!
//! let mut seed = Seed::default();
//! OsRng.fill_bytes(seed.as_mut_slice());
//! let aux_data = None;
//!
//! let (mut signing_key, verifying_key) =
//!     hbs_lms::keygen::<Sha256_256>(&hss_parameter, &seed, aux_data).unwrap();
//!
//! let signature = signing_key.try_sign(&message).unwrap();
//!
//! let valid_signature = verifying_key.verify(&message, &signature);
//!
//! assert_eq!(valid_signature.is_ok(), true);
//! ```
//!
//! # Environment Variables
//!
//! To adapt the internals of the crate, the user can set the following environment variables:
//!
//! ## Adapting the crate in general
//!
//! These three environment variables listed below, adapt the internals of the crate and can be used
//! to reduce the required stack size. The values are used to set the maximum size of the arrays
//! used for computation and storing intermediate values.
//!
//! Any change limits the functionality of this crate, as no longer all possible parameters are
//! supported! (For example setting `HBS_LMS_MAX_ALLOWED_HSS_LEVELS` to 1 allows only for a single
//! tree.)
//!
//! The length of the tree height and the winternitz parameter arrays must match the value of the
//! HSS levels.
//!
//! | Name                           | Default | Range of Values    | Description             |
//! |--------------------------------|---------|--------------------|-------------------------|
//! | HBS_LMS_MAX_ALLOWED_HSS_LEVELS | 8       | 1..8               | Max. tree count for HSS |
//! | HBS_LMS_TREE_HEIGHTS           | [25; 8] | [`LmsAlgorithm`]   | Max. Tree Height for each tree|
//! | HBS_LMS_WINTERNITZ_PARAMETERS  | [1; 8]  | [`LmotsAlgorithm`] | Min. Winternitz Parameter for each tree |
//!
//! Reducing the HSS levels or the values of the tree heights lead to a reduced stack usage. For the
//! values of the Winternitz parameter the inverse must be applied, as higher Winternitz parameters
//! reduce the stack usage.
//!
//! ## Adapting wrt the 'fast_verify' feature
//!
//! The 'fast_verify' features enables this crate to sign fast verifiable signatures. The drawback
//! is more computative effort on the side of the signer. With the these two environment variables
//! listed below, the user can adapt effect.
//!
//! | Name                           | Default | Description                      |
//! |--------------------------------|---------|----------------------------------|
//! | HBS_LMS_MAX_HASH_OPTIMIZATIONS | 10_000  | Try count to optimize the hash   |
//! | HBS_LMS_THREADS                | 1       | Thread count to split the effort |
//!
//! If the crate is compiled with the std library, the effort of the generation of fast verifiable
//! signatures can be split to multiple threads using the `HBS_LMS_THREADS`.

extern crate core;

mod constants;
mod hasher;
mod hss;
mod lm_ots;
mod lms;
mod util;

// Re-export the `signature` crate
pub use signature::{self};

#[doc(hidden)]
pub use crate::constants::MAX_HASH_SIZE;
#[doc(hidden)]
pub use crate::hss::reference_impl_private_key::Seed;

pub use crate::hasher::{
    sha256::{Sha256_128, Sha256_192, Sha256_256},
    shake256::{Shake256_128, Shake256_192, Shake256_256},
    HashChain, HashChainData,
};

pub use crate::hss::parameter::HssParameter;
pub use crate::lm_ots::parameters::LmotsAlgorithm;
pub use crate::lms::parameters::LmsAlgorithm;

pub use crate::hss::hss_keygen as keygen;
pub use crate::hss::hss_sign as sign;
#[cfg(feature = "fast_verify")]
pub use crate::hss::hss_sign_mut as sign_mut;
pub use crate::hss::hss_verify as verify;
pub use crate::hss::{SigningKey, VerifyingKey};

use core::convert::TryFrom;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr;
use core::slice;
use signature::{Error, Verifier};
use tinyvec::ArrayVec;

use crate::constants::{MAX_HSS_PUBLIC_KEY_LENGTH, REF_IMPL_MAX_PRIVATE_KEY_SIZE};
use constants::MAX_HSS_SIGNATURE_LENGTH;

/**
 * Implementation of [`signature::Signature`].
 */
#[derive(Debug)]
pub struct Signature {
    bytes: ArrayVec<[u8; MAX_HSS_SIGNATURE_LENGTH]>,
    #[cfg(feature = "verbose")]
    pub hash_iterations: u32,
}

impl Signature {
    pub(crate) fn from_bytes_verbose(bytes: &[u8], _hash_iterations: u32) -> Result<Self, Error> {
        let bytes = ArrayVec::try_from(bytes).map_err(|_| Error::new())?;

        Ok(Self {
            bytes,
            #[cfg(feature = "verbose")]
            hash_iterations: _hash_iterations,
        })
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Signature::from_bytes_verbose(bytes, 0)
    }
}

/**
 * No-copy friendly alternative to [`Signature`] by using a reference to a slice of bytes (for
 * verification only!).
 */
#[derive(Debug)]
pub struct VerifierSignature<'a> {
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> VerifierSignature<'a> {
    pub fn from_ref(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(Self { bytes })
    }
}

impl<'a> AsRef<[u8]> for VerifierSignature<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> signature::Signature for VerifierSignature<'a> {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        Err(Error::new())
    }
}

/*
 * BEGIN C BINDINGS
 */

// Types used for extern C

// Change this for different hash functions
type Hasher = Sha256_256;

#[allow(non_camel_case_types)]
type c_int = i32;
#[allow(non_camel_case_types)]
type c_char = i8;

extern "C" {
    /// Prints out `msg`
    pub fn hal_send_str(msg: *const c_char);
    /// Writes `len` random bytes to `dest`
    pub fn randombytes(dest: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn do_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int {
    let seed = Seed::default();

    // random seed
    unsafe { randombytes(seed.as_slice().as_ptr(), seed.len()) }

    // fixed seed
    // let seed_values: [u8; MAX_SEED_LEN] = [
    //     125, 43, 194, 148, 228, 228, 109, 53, 178, 168, 154, 26, 105, 33, 56, 139, 144, 32, 20, 157,
    //     252, 187, 167, 93, 172, 133, 194, 255, 194, 100, 197, 225,
    // ];
    // seed.as_mut_slice()
    //     .copy_from_slice(&seed_values[..(Hasher::OUTPUT_SIZE as usize)]);

    let (signing_key, verifying_key) =
        match keygen::<Hasher>(&[HssParameter::construct_default_parameters()], &seed, None) {
            Ok(keypair) => keypair,
            Err(_) => {
                return -1;
            }
        };

    unsafe {
        ptr::copy(signing_key.bytes.as_ptr(), sk, signing_key.bytes.len());
        ptr::copy(verifying_key.bytes.as_ptr(), pk, verifying_key.bytes.len());
    }
    0
}

#[no_mangle]
pub extern "C" fn do_crypto_sign(
    sm: *mut u8,
    smlen: *mut usize,
    m: *const u8,
    mlen: usize,
    sk: *const u8,
) -> c_int {
    let msg = unsafe { slice::from_raw_parts(m, mlen) };

    let mut signing_key = SigningKey::<Hasher>::from_bytes(unsafe {
        slice::from_raw_parts(sk, REF_IMPL_MAX_PRIVATE_KEY_SIZE)
    })
    .unwrap();

    let signing_key_const = signing_key.clone();

    let mut update_private_key = |new_key: &[u8]| {
        signing_key.as_mut_slice().copy_from_slice(new_key);
        Ok(())
    };

    let signature = match sign::<Hasher>(
        &msg,
        signing_key_const.as_slice(),
        &mut update_private_key,
        None,
    ) {
        Ok(signature) => signature,
        Err(_) => return -1,
    };

    let sig_len = signature.bytes.len();

    unsafe {
        smlen.write(size_of::<u32>() + msg.len() + sig_len);
        sm.cast::<u32>().write(signature.bytes.len() as u32);
        ptr::copy_nonoverlapping(
            msg.as_ptr(),
            sm.offset(size_of::<u32>() as isize),
            msg.len(),
        );
        ptr::copy_nonoverlapping(
            signature.bytes.as_ptr(),
            sm.offset((size_of::<u32>() + msg.len()) as isize),
            sig_len,
        );
    }

    0
}

#[no_mangle]
pub extern "C" fn do_crypto_sign_open(
    m: *mut u8,
    mlen: *mut usize,
    sm: *const u8,
    smlen: usize,
    pk: *const u8,
) -> c_int {
    if smlen < size_of::<u32>() {
        return -1;
    }

    let sig_len = unsafe { sm.cast::<u32>().read() as usize };
    if smlen < sig_len {
        return -1;
    }

    let msg_len = smlen - size_of::<u32>() - sig_len;
    if smlen < sig_len + msg_len + size_of::<u32>() {
        return -1;
    }
    unsafe {
        mlen.write(msg_len);
    }
    let msg =
        unsafe { slice::from_raw_parts_mut(m.offset(size_of::<u32>() as isize), msg_len) };

    let verifying_key = VerifyingKey::<Hasher>::from_bytes(unsafe {
        slice::from_raw_parts(pk, MAX_HSS_PUBLIC_KEY_LENGTH)
    })
    .unwrap();

    let signature = Signature::from_bytes_verbose(
        unsafe { slice::from_raw_parts(sm.offset((size_of::<u32>() + msg_len) as isize), sig_len) },
        0,
    )
    .unwrap();

    // print key
    /*
    let mut keyout = [0x20u8; 48 * 3];
    keyout[143] = 0;
    for i in 0..48 {
        keyout[3 * i] = (signature.bytes[i] >> 4) + 0x30u8;
        keyout[3 * i + 1] = (signature.bytes[i] & 0xf) + 0x30u8;
    }
    unsafe {
        hal_send_str( keyout.as_ptr().cast());
    }
     */

    match verifying_key.verify(msg, &signature) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn do_crypto_sign_signature(
    _sig: *mut u8,
    _siglen: *mut usize,
    _m: *const u8,
    _mlen: usize,
    _sk: *const u8,
) -> c_int {
    unimplemented!()
}

#[no_mangle]
pub extern "C" fn do_crypto_sign_verify(
    sig: *const u8,
    siglen: usize,
    m: *const u8,
    mlen: usize,
    pk: *const u8,
) -> c_int {
    let msg = unsafe { slice::from_raw_parts(m, mlen) };

    let verifying_key = VerifyingKey::<Hasher>::from_bytes(unsafe {
        slice::from_raw_parts(pk, MAX_HSS_PUBLIC_KEY_LENGTH)
    })
    .unwrap();

    let signature =
        Signature::from_bytes_verbose(unsafe { slice::from_raw_parts(sig, siglen) }, 0).unwrap();

    // print key
    /*
    let mut keyout = [0x20u8; 48 * 3];
    keyout[143] = 0;
    for i in 0..48 {
        keyout[3 * i] = (signature.bytes[i] >> 4) + 0x30u8;
        keyout[3 * i + 1] = (signature.bytes[i] & 0xf) + 0x30u8;
    }
    unsafe {
        hal_send_str( keyout.as_ptr().cast());
    }
     */

    match verifying_key.verify(msg, &signature) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[panic_handler]
pub fn panic(reason: &PanicInfo) -> ! {
    unsafe {
        let out = [112, 97, 110, 105, 99, 0x00];
        hal_send_str(out.as_ptr());
    }

    if let Some(msg) = reason.payload().downcast_ref::<&str>() {
        unsafe {
            hal_send_str(msg.as_bytes().as_ptr().cast());
        }
    } else {
        unsafe {
            let out = [32, 98, 117, 116, 32, 119, 104, 121, 0];
            hal_send_str(out.as_ptr());
        }
    }

    loop {}
}

/*
 * END C BINDINGS
 */

#[cfg(test)]
mod tests {
    use crate::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Sha256_256};
    use crate::{
        signature::{SignerMut, Verifier},
        SigningKey, VerifierSignature, VerifyingKey,
    };

    use crate::util::helper::test_helper::gen_random_seed;

    #[test]
    fn get_signing_and_verifying_key() {
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let (signing_key, verifying_key) = keygen::<H>(
            &[HssParameter::new(
                LmotsAlgorithm::LmotsW2,
                LmsAlgorithm::LmsH5,
            )],
            &seed,
            None,
        )
        .unwrap();

        let _: SigningKey<H> = signing_key;
        let _: VerifyingKey<H> = verifying_key;
    }

    #[test]
    fn signature_trait() {
        let message = [
            32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
        ];
        type H = Sha256_256;
        let seed = gen_random_seed::<H>();

        let (mut signing_key, verifying_key) = keygen::<H>(
            &[
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
                HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            ],
            &seed,
            None,
        )
        .unwrap();

        let signature = signing_key.try_sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());

        let ref_signature = VerifierSignature::from_ref(signature.as_ref()).unwrap();

        assert!(verifying_key.verify(&message, &ref_signature).is_ok());
    }
}
