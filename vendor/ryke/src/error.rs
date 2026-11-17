use thiserror::Error;

/// Errors from parsing or processing IKEv2 messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IkeError {
    // --- wire parsing ---
    /// The buffer ended before a fixed-size field could be read.
    #[error("truncated input: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },

    /// A declared length pointed past the end of the buffer.
    #[error("declared length {declared} exceeds available {available} bytes")]
    BadLength { declared: usize, available: usize },

    /// A generic payload header declared a length smaller than the 4-byte header
    /// itself, which would loop forever.
    #[error("payload length {0} is smaller than the 4-byte generic header")]
    ShortPayload(u16),

    // --- exchange processing ---
    /// A payload required for this exchange was absent.
    #[error("required {0} payload is missing")]
    MissingPayload(&'static str),

    /// None of the offered proposals used a suite we support.
    #[error("no supported proposal in the offered SA")]
    NoProposalChosen,

    /// The peer's Key Exchange used a DH group other than the negotiated one.
    #[error("DH group mismatch: expected {expected}, got {got}")]
    DhGroupMismatch { expected: u16, got: u16 },

    /// The Key Exchange data length is wrong for its DH group.
    #[error("key exchange data for group {group} has wrong length {len}")]
    BadKeyExchange { group: u16, len: usize },

    /// AEAD (GCM) authentication of an SK payload failed — wrong key, wrong
    /// associated data, or tampering.
    #[error("SK payload authentication failed")]
    BadIntegrity,

    /// The peer's AUTH payload did not verify (wrong PSK or altered SA_INIT).
    #[error("peer authentication (AUTH payload) failed")]
    AuthFailed,

    /// A cryptographic precondition was violated (e.g. bad key length).
    #[error("crypto error: {0}")]
    Crypto(&'static str),
}
