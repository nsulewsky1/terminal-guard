//! Canonical, unambiguous binary encoding used for everything that is hashed
//! or signed. Every variable-length field is length-prefixed, integers are
//! fixed-width big-endian, and every structure starts with a 4-byte magic and
//! a version byte so different message types can never be confused.

pub(crate) struct Enc(Vec<u8>);

impl Enc {
    pub(crate) fn new(magic: &[u8; 4], version: u8) -> Self {
        let mut v = Vec::with_capacity(128);
        v.extend_from_slice(magic);
        v.push(version);
        Enc(v)
    }
    pub(crate) fn u8(&mut self, x: u8) -> &mut Self {
        self.0.push(x);
        self
    }
    pub(crate) fn u64(&mut self, x: u64) -> &mut Self {
        self.0.extend_from_slice(&x.to_be_bytes());
        self
    }
    pub(crate) fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        // Inputs are length-limited by validation well below u32::MAX.
        let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }
    pub(crate) fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    pub(crate) fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Identifiers (engine IDs, action names) are short printable ASCII so they
/// are unambiguous in logs and cannot smuggle control characters.
pub(crate) fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
}
