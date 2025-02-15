use crate::{
    security::{
        backend::PkiBackendTrait,
        certificate::{
            CertificateTrait, CertificateWithHashContainer, EnrollmentAuthorityCertificate,
            ExplicitCertificate,
        },
        ciphertext::Ciphertext,
        permission::Permission,
        pki::{
            encrypted_data::EncryptedData,
            kdf2,
            message::{
                self,
                enrollment::{EnrollmentRequest, EnrollmentRequestError, EnrollmentRequestResult},
                RecipientInfo,
            },
            service::{PkiServiceError, PkiServiceResult},
            Aes128Key,
        },
        ssp::{
            scr::{ScrPermission, ScrSsp},
            SspTrait,
        },
        EcKeyType, EcdsaKey, EncryptedEciesKey, HashAlgorithm, KeyPair,
    },
    time::Instant,
};

use super::PkiClientService;

impl PkiClientService {
    pub fn enrollment_request(
        &self,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        timestamp: Instant,
    ) -> PkiServiceResult<Vec<u8>> {
        let backend = self.backend.inner_pki();

        // Generate the Enrollment Credential key pair.
        let ec_pubkey = backend
            .generate_enrollment_keypair(EcKeyType::NistP256r1)
            .map_err(PkiServiceError::Backend)?
            .try_into()
            .map_err(PkiServiceError::Backend)?;

        // Generate the AES 128 ephemeral encryption key.
        let symm_encryption_key = Aes128Key(
            backend
                .generate_aes128_key()
                .map_err(PkiServiceError::Backend)?,
        );

        let (res, _ephemeral_keypair) = self
            .enrollment_request_inner(
                &ec_pubkey,
                &symm_encryption_key,
                ea_certificate,
                timestamp,
                backend,
            )
            .map_err(PkiServiceError::EnrollmentRequest)?;

        Ok(res)
    }

    fn enrollment_request_inner<B>(
        &self,
        pubkey: &EcdsaKey,
        symm_encryption_key: &Aes128Key,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> EnrollmentRequestResult<(Vec<u8>, KeyPair<B::BackendSecretKey, B::BackendPublicKey>)>
    where
        B: PkiBackendTrait,
    {
        let hash_algorithm = pubkey.hash_algorithm();
        let canonical_pubkey: EcdsaKey = backend
            .canonical_pubkey()
            .map_err(EnrollmentRequestError::Backend)?
            .ok_or(EnrollmentRequestError::NoCanonicalKey)?
            .try_into()
            .map_err(EnrollmentRequestError::Backend)?;

        let mut request = EnrollmentRequest::new(self.canonical_id.as_bytes().to_vec());

        // Add Enrollment Credential permissions.
        let mut ssp = ScrSsp::new();
        ssp.set_permission(ScrPermission::AuthorizationReq); // Allow authorization ticket request signing.
        ssp.set_permission(ScrPermission::EnrollmentReq); // Allow enrollment request signing for re-enrollment.

        request.set_app_permissions(vec![Permission::SCR(ssp.into())]);
        request.set_verification_key(pubkey.to_owned())?;

        // Create Inner EC Request for POP wrapper and sign it with the enrollment key.
        let mut signed_for_pop =
            EnrollmentRequest::emit_inner_ec_request_for_pop(request, timestamp)?;

        message::sign_data_with_enrollment_key(&mut signed_for_pop, hash_algorithm, backend)
            .map_err(EnrollmentRequestError::SignedForPopSigner)?;

        // Create Outer EC Request and sign it with the canonical key.
        let mut outer_ec_request =
            EnrollmentRequest::emit_outer_ec_request(signed_for_pop, timestamp)?;

        let hash_algorithm = canonical_pubkey.hash_algorithm();

        message::sign_data_with_canonical_key(&mut outer_ec_request, hash_algorithm, backend)
            .map_err(EnrollmentRequestError::OuterSigner)?;

        // Serialize the outer EC Request to COER bytes.
        let to_encrypt = outer_ec_request
            .as_bytes()
            .map_err(EnrollmentRequestError::Outer)?;

        // Generate the nonce associated with the encryption key.
        let nonce = backend
            .generate_random::<12>()
            .map_err(EnrollmentRequestError::Backend)?;

        // Encrypt the outer EC Request.
        let encrypted_req = backend
            .encrypt_aes128_ccm(&to_encrypt, &symm_encryption_key.0, &nonce)
            .map_err(EnrollmentRequestError::Backend)?;

        // Encrypt the encryption key.
        let cert_hashed_id8 = ea_certificate.hashed_id8();
        let public_encryption_key = ea_certificate
            .certificate()
            .public_encryption_key()
            .map_err(EnrollmentRequestError::Certificate)?
            .ok_or(EnrollmentRequestError::NoPublicEncryptionKey)?;

        let key_type = public_encryption_key.key_type();
        let hash_algorithm = public_encryption_key.hash_algorithm();

        let ephemeral_ec_encryption_keypair = backend
            .generate_ephemeral_keypair(key_type)
            .map_err(EnrollmentRequestError::Backend)?;

        let peer_public_key = B::BackendPublicKey::try_from(public_encryption_key)
            .map_err(EnrollmentRequestError::Backend)?;

        // Build the shared secret.
        let shared_secret = backend
            .derive(&ephemeral_ec_encryption_keypair.secret, &peer_public_key)
            .map_err(EnrollmentRequestError::Backend)?;

        let cert_hash = ea_certificate.certificate().hash(hash_algorithm, backend);

        let (ke_size, km_size) = match hash_algorithm {
            HashAlgorithm::SHA256 | HashAlgorithm::SM3 => (16, 32),
            HashAlgorithm::SHA384 => (24, 48),
        };

        let ke_km = kdf2(
            &shared_secret,
            &cert_hash,
            ke_size + km_size,
            hash_algorithm,
            backend,
        );

        // Encrypt the encryption key.
        let encrypted_key: Vec<u8> = symm_encryption_key
            .0
            .iter()
            .zip(ke_km[..ke_size].iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Generate the associated tag.
        let tag = backend
            .hmac(hash_algorithm, &ke_km[ke_size..], &encrypted_key)
            .map_err(EnrollmentRequestError::Backend)?;

        let ciphertext = Ciphertext::new_aes_128_ccm(nonce.into(), encrypted_req);

        // Get the ephemeral public key into the correct format.
        let ephemeral_public_key = ephemeral_ec_encryption_keypair
            .public
            .clone()
            .try_into()
            .map_err(EnrollmentRequestError::Backend)?;

        let enc_key = EncryptedEciesKey::new(ephemeral_public_key, encrypted_key, tag);
        let recipient = RecipientInfo::new_cert(cert_hashed_id8, enc_key);
        let encrypted_wrapper = EncryptedData::new(ciphertext, vec![recipient])
            .map_err(EnrollmentRequestError::Encrypted)?;

        Ok((
            encrypted_wrapper
                .as_bytes()
                .map_err(EnrollmentRequestError::Encrypted)?,
            ephemeral_ec_encryption_keypair,
        ))
    }
}
