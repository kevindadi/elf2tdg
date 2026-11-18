//! Analyzer error types.

use std::path::PathBuf;

/// Fatal analyzer errors. Recoverable issues are reported as CFG diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading the input file failed.
    #[error("failed to read {path}: {source}")]
    ReadFile {
        /// Input path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The ELF parser rejected the image.
    #[error("failed to parse ELF image: {0}")]
    Elf(String),
    /// The image has no executable sections.
    #[error("image contains no executable sections")]
    NoExecutableSections,
    /// The image's machine/architecture is not supported.
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    /// Capstone initialization failed.
    #[error("failed to initialize the {arch} disassembler: {message}")]
    DecoderInit {
        /// Architecture name.
        arch: &'static str,
        /// Capstone error text.
        message: String,
    },
    /// Instruction decoding failed.
    #[error("failed to decode instruction at 0x{address:x}: {message}")]
    Decode {
        /// Instruction address.
        address: u64,
        /// Decoder error text.
        message: String,
    },
    /// An analysis resource limit was exceeded.
    #[error("analysis limit exceeded: {0}")]
    Limit(String),
    /// Invalid configuration supplied by the caller.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// The intermediate CFG failed structural validation.
    #[error("CFG validation failed: {0}")]
    CfgValidation(String),
    /// Serialization failed.
    #[error("failed to serialize output: {0}")]
    Serialize(String),
    /// Writing output failed.
    #[error("failed to write {path}: {source}")]
    WriteFile {
        /// Output path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, Error>;
