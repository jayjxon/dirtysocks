//! Randomness for ephemeral keys, nonces, and SPIs.
//!
//! Abstracted behind [`Entropy`] so the exchange logic stays deterministic and
//! testable: production uses [`OsEntropy`] (the OS CSPRNG), tests use
//! [`SeedEntropy`] (a deterministic PRNG — never use it in production).

/// A source of random bytes.
pub trait Entropy {
    /// Fill `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]);

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_be_bytes(b)
    }

    fn next_array32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
}

/// OS cryptographic randomness, read from `/dev/urandom` (Linux/unix).
#[cfg(unix)]
pub struct OsEntropy {
    file: std::fs::File,
}

#[cfg(unix)]
impl OsEntropy {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { file: std::fs::File::open("/dev/urandom")? })
    }
}

#[cfg(unix)]
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        use std::io::Read;
        self.file
            .read_exact(out)
            .expect("read from /dev/urandom must not fail");
    }
}

/// Deterministic PRNG (SplitMix64) for tests only. **Not** cryptographically
/// secure — do not use for real key material.
pub struct SeedEntropy {
    state: u64,
}

impl SeedEntropy {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Entropy for SeedEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next().to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_entropy_is_deterministic_and_varied() {
        let mut a = SeedEntropy::new(42);
        let mut b = SeedEntropy::new(42);
        assert_eq!(a.next_array32(), b.next_array32());

        let mut c = SeedEntropy::new(42);
        // Two consecutive draws should differ.
        assert_ne!(c.next_array32(), c.next_array32());
    }
}
