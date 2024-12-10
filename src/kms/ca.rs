// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use rcgen::{
    Certificate, CertificateParams, CertificateSigningRequest, DnType, ExtendedKeyUsagePurpose,
    KeyPair, KeyUsagePurpose,
};

pub struct CA {
    ca: Certificate,
}

impl CA {
    pub fn new(private_key: String, public_key_cert: String) -> Result<Self> {
        let key_pair = KeyPair::from_pem(&private_key)?;

        let ca = CertificateParams::from_ca_cert_pem(&public_key_cert, key_pair)?;
        let ca = Certificate::from_params(ca)?;
        Ok(Self { ca })
    }

    pub fn issue_cert(&self, mut csr: CertificateSigningRequest) -> Result<String> {
        csr.params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        csr.params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        csr.params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        csr.params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        csr.params.distinguished_name.remove(DnType::CommonName);
        csr.params
            .distinguished_name
            .push(DnType::CommonName, "TEE-KMS Client Cert");

        let cert = csr.serialize_pem_with_signer(&self.ca)?;

        Ok(cert)
    }
}
