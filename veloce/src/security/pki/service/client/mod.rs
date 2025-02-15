use crate::security::SecurityBackend;

pub mod enrollment;

pub struct PkiClientService {
   /// Unique identifier of the local ITS station.
   canonical_id: String,
   /// Cryptography backend.
   backend: SecurityBackend,
}

impl PkiClientService {
   /// Constructs a [PkiClientService].
   pub fn new(canonical_id: String, backend: SecurityBackend) -> Self {
       Self { canonical_id, backend }
   }
}
