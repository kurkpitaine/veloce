
# Refactoring
- * Check EtsiTs102941Data wrapper usage.
- * Rework AT certificate request code.
- * Rework PKI response handling. Many responses share the same structure nesting construction. Find a way to avoid code duplication.
- Rework crypto backend Trait on signature methods: shift towards a unique sign() method with an enum as argument to select the key used for signing ?
- Find a way to ease the load/store of certificates in the stack: add a TrustStorageProvider trait to use in conjunction with the TrustStore.
- Current implementation of TrustStore (storing certificates) is decoupled from the crypto backend (storing the private keys). Find an elegant way to ensure
  local EnrollmentCredentialCertificate and AuthorizationTicket certificates <-> private keys association are always consistent.
-  Rework SignedData on both PKI and Security modules. Find a way to accept multiple inner 'Signed' types (for the PKI) and merge with the Security SecuredMessage module.

# Implementation
- Interface to feed the stack with data from the vehicle.
- Implement Re-enrollment procedure.
- Implement ECTL + TLM parsing and storage of contained root certificates.
- Implement CTL and CRL parsing and storage of EA and AA certificates.
- Implement AT certificate request/download with Butterfly keys.

# Tools
- 'to-be-named' CLI tool to manage PKI: ECTL download, Enrollment procedure, AT download, certificates validity and storage.
- 'veloce-ctl' CLI tool to manage the stack, ideally via an Unix socket.
