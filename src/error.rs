use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BcError {
    #[error("too many erasures: {erased} known symbols but need at least {needed}")]
    TooFewKnownSymbols { erased: usize, needed: usize },

    #[error("erasures could not be resolved by the local/pairwise decoder (uncorrectable pattern)")]
    Uncorrectable,

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("message length {got} does not match code dimension k={expected}")]
    BadMessageLength { got: usize, expected: usize },

    #[error("codeword length {got} does not match code length n={expected}")]
    BadCodewordLength { got: usize, expected: usize },
}
