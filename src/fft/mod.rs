//! FFT-based encoders and decoders for BCC and 2D-RS.

pub mod bcc;
pub mod rs;
pub mod rs2d;

pub use bcc::{FftBlockCirculantCode, decode};
pub use rs2d::FftTwoDRsCode;
