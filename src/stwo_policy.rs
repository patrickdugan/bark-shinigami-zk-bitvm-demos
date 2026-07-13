use crate::envelope::tagged_sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StwoPolicyV1 {
    pub pow_bits: u8,
    pub interaction_pow_bits: u8,
    pub log_blowup_factor: u8,
    pub n_queries: u8,
    pub log_last_layer_degree_bound: u8,
    pub fold_step: u8,
    pub lifting_log_size: Option<u8>,
    pub channel: Channel,
    pub preprocessed_variant: PreprocessedVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Blake2s,
    Poseidon252,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreprocessedVariant {
    Canonical,
    Legacy,
}

impl StwoPolicyV1 {
    pub const REQUIRED: Self = Self {
        pow_bits: 26,
        interaction_pow_bits: 24,
        log_blowup_factor: 1,
        n_queries: 70,
        log_last_layer_degree_bound: 0,
        fold_step: 1,
        lifting_log_size: None,
        channel: Channel::Blake2s,
        preprocessed_variant: PreprocessedVariant::Canonical,
    };

    pub fn canonical_bytes(self) -> [u8; 11] {
        [
            1,
            self.pow_bits,
            self.interaction_pow_bits,
            self.log_blowup_factor,
            self.n_queries,
            self.log_last_layer_degree_bound,
            self.fold_step,
            self.lifting_log_size.unwrap_or(u8::MAX),
            match self.channel {
                Channel::Blake2s => 1,
                Channel::Poseidon252 => 2,
            },
            match self.preprocessed_variant {
                PreprocessedVariant::Canonical => 1,
                PreprocessedVariant::Legacy => 2,
            },
            0,
        ]
    }

    pub fn digest(self) -> [u8; 32] {
        tagged_sha256("BarkZkBitvm/StwoPolicyV1", &self.canonical_bytes())
    }

    pub fn enforce(self) -> Result<(), StwoPolicyError> {
        if self == Self::REQUIRED {
            Ok(())
        } else {
            Err(StwoPolicyError { observed: self })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StwoPolicyError {
    pub observed: StwoPolicyV1,
}

impl std::fmt::Display for StwoPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "STWO proof policy does not exactly match StwoPolicyV1")
    }
}

impl std::error::Error for StwoPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_policy_is_required() {
        assert!(StwoPolicyV1::REQUIRED.enforce().is_ok());
        let mut weak = StwoPolicyV1::REQUIRED;
        weak.n_queries = 1;
        assert!(weak.enforce().is_err());
        assert_ne!(weak.digest(), StwoPolicyV1::REQUIRED.digest());
    }

    #[test]
    fn channel_and_preprocessing_are_pinned() {
        let mut changed = StwoPolicyV1::REQUIRED;
        changed.channel = Channel::Poseidon252;
        assert!(changed.enforce().is_err());
        changed = StwoPolicyV1::REQUIRED;
        changed.preprocessed_variant = PreprocessedVariant::Legacy;
        assert!(changed.enforce().is_err());
    }
}
