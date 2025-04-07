pub mod authorization;
pub mod enrollment;

pub struct PkiClientService {
    /// Unique identifier of the local ITS station.
    canonical_id: String,
}

impl PkiClientService {
    /// Constructs a [PkiClientService].
    pub fn new(canonical_id: String) -> Self {
        Self { canonical_id }
    }
}
