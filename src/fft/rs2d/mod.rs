//! FFT-based row/column encoder and decoder for the 2D-RS baseline.
//!
//! The message occupies the `k0 x k0` systematic grid. Encoding first
//! extends message rows, then extends the resulting columns. Decoding applies
//! the inverse process by repeatedly repairing rows and columns.

pub mod decoder;
pub mod encode;

pub use encode::FftTwoDRsCode;
