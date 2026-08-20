//! Binary envelope framing and ciphertext hashes.

use crate::{
    error::{ProtocolError, Result},
    keccak::keccak256,
};

/// Recipient HPKE info label.
pub const RECIPIENT_INFO: &str = "haze/avalanche/v1/recipient-note";
/// Audit HPKE info label.
pub const AUDIT_INFO: &str = "haze/avalanche/v1/audit-record";

const MAGIC: &[u8; 4] = b"HZHP";
const ENVELOPE_VERSION: u8 = 1;
const PURPOSE_RECIPIENT: u8 = 1;
const PURPOSE_AUDIT: u8 = 2;
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;
const X25519_ENCAP_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;

/// Purpose of a Haze HPKE envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopePurpose {
    /// Recipient note delivery.
    Recipient,
    /// Institutional audit record.
    Audit,
}

/// Canonical binary envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Envelope purpose.
    pub purpose: EnvelopePurpose,
    /// Application or audit key version, or zero for recipient notes.
    pub key_version: u64,
    /// HPKE encapsulated key.
    pub encapsulated_key: Vec<u8>,
    /// Authenticated ciphertext.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    fn validate(&self) -> Result<()> {
        if matches!(self.purpose, EnvelopePurpose::Recipient) && self.key_version != 0 {
            return Err(ProtocolError::EncodingInvalid);
        }
        if self.encapsulated_key.len() != X25519_ENCAP_LEN {
            return Err(ProtocolError::EncodingInvalid);
        }
        if self.ciphertext.len() < AEAD_TAG_LEN || self.ciphertext.len() > u32::MAX as usize {
            return Err(ProtocolError::EncodingInvalid);
        }
        Ok(())
    }

    /// Encode the complete binary envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let purpose = match self.purpose {
            EnvelopePurpose::Recipient => PURPOSE_RECIPIENT,
            EnvelopePurpose::Audit => PURPOSE_AUDIT,
        };
        let encap_len = u16::try_from(self.encapsulated_key.len())
            .map_err(|_| ProtocolError::EncodingInvalid)?;
        let ciphertext_len =
            u32::try_from(self.ciphertext.len()).map_err(|_| ProtocolError::EncodingInvalid)?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(purpose);
        out.extend_from_slice(&KEM_ID.to_be_bytes());
        out.extend_from_slice(&KDF_ID.to_be_bytes());
        out.extend_from_slice(&AEAD_ID.to_be_bytes());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(&encap_len.to_be_bytes());
        out.extend_from_slice(&self.encapsulated_key);
        out.extend_from_slice(&ciphertext_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Decode a complete binary envelope and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const FIXED: usize = 4 + 1 + 1 + 2 + 2 + 2 + 8 + 2;
        if bytes.len() < FIXED + 4 {
            return Err(ProtocolError::EncodingInvalid);
        }
        if &bytes[..4] != MAGIC {
            return Err(ProtocolError::EncodingInvalid);
        }
        if bytes[4] != ENVELOPE_VERSION {
            return Err(ProtocolError::VersionUnsupported);
        }
        let purpose = match bytes[5] {
            PURPOSE_RECIPIENT => EnvelopePurpose::Recipient,
            PURPOSE_AUDIT => EnvelopePurpose::Audit,
            _ => return Err(ProtocolError::EncodingInvalid),
        };
        let kem = u16::from_be_bytes([bytes[6], bytes[7]]);
        let kdf = u16::from_be_bytes([bytes[8], bytes[9]]);
        let aead = u16::from_be_bytes([bytes[10], bytes[11]]);
        if kem != KEM_ID || kdf != KDF_ID || aead != AEAD_ID {
            return Err(ProtocolError::EncodingInvalid);
        }
        let key_version = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| ProtocolError::EncodingInvalid)?,
        );
        let encap_len = usize::from(u16::from_be_bytes([bytes[20], bytes[21]]));
        let encap_end = FIXED
            .checked_add(encap_len)
            .ok_or(ProtocolError::EncodingInvalid)?;
        let ct_len_end = encap_end
            .checked_add(4)
            .ok_or(ProtocolError::EncodingInvalid)?;
        if bytes.len() < ct_len_end {
            return Err(ProtocolError::EncodingInvalid);
        }
        let ciphertext_len = u32::from_be_bytes(
            bytes[encap_end..ct_len_end]
                .try_into()
                .map_err(|_| ProtocolError::EncodingInvalid)?,
        ) as usize;
        let end = ct_len_end
            .checked_add(ciphertext_len)
            .ok_or(ProtocolError::EncodingInvalid)?;
        if bytes.len() != end {
            return Err(ProtocolError::EncodingInvalid);
        }
        let envelope = Self {
            purpose,
            key_version,
            encapsulated_key: bytes[FIXED..encap_end].to_vec(),
            ciphertext: bytes[ct_len_end..end].to_vec(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Keccak-256 over the complete binary envelope.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(keccak256(&self.to_bytes()?))
    }
}
