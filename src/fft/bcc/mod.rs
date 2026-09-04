//! FFT-based construction of `C_BC[mu, 2, omega, rho]`, matching
//! Sasidharan/Viterbo/Feist, "Block Circulant Codes for Ethereum PeerDAS"
//! (the practical follow-up to the original theory paper this crate is
//! primarily based on). See [`points`] for the evaluation-point
//! construction (the *restricted* FFT technique, Sec. 4.1),
//! [`crate::fft::rs`] for the shared FFT-based erasure-decoding primitive,
//! and [`code`]/[`decoder`] for the encoder/decoder built on top of them.
//!
//! Requires `F: FftField` (BLS12-381's `Fr` qualifies) and `omega`,
//! `rho+omega` to both be powers of 2 — see [`points`]'s module docs for why.

pub mod decoder;
pub mod encode;
pub mod points;
pub mod topology;

pub use decoder::decode;
pub use encode::FftBlockCirculantCode;
pub use points::FftPoints;
