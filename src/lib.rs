//! FFT-based BCC and 2D-RS encoding and decoding.
#![allow(
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::manual_is_multiple_of,
    clippy::manual_repeat_n,
    clippy::needless_range_loop,
    clippy::type_complexity
)]
pub mod archive;
pub mod error;
pub mod fft;

// Defines BCC dimensions and support layout.

pub use error::BcError;
pub use fft::bcc::topology::BcParams;
pub use fft::{decode, FftBlockCirculantCode};
