use anyhow::{Result, anyhow};
use rand::random_range;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use std::path::PathBuf;
use time::{Duration, OffsetDateTime};

const ROOT_KEY_FILENAME: &str = "zpki-root-key.pem";
const ROOT_CERT_FILENAME: &str = "zpki-root-cert.pem";
const LEAF_KEY_FILENAME: &str = "key.pem";
const LEAF_CERT_FILENAME: &str = "cert.pem";
const VALIDITY_DAYS: u32 = 730;

pub enum ZpkiType {
    RootKey,
    RootCert,
    Key,
    Cert,
}

impl ZpkiType {
    fn filename(&self) -> &'static str {
        match self {
            ZpkiType::RootKey => ROOT_KEY_FILENAME,
            ZpkiType::RootCert => ROOT_CERT_FILENAME,
            ZpkiType::Key => LEAF_KEY_FILENAME,
            ZpkiType::Cert => LEAF_CERT_FILENAME,
        }
    }
}

/// Generates the default certificate parameters for a root CA certificate of 2 years validity
pub fn root_params() -> Result<CertificateParams> {
    // generate default certificate params with SAN
    let mut params = CertificateParams::new(Vec::new())?;

    let random_number: u32 = random_range(0..9999);
    let cn = format!("ZPKI root ca {}", random_number);
    params.distinguished_name.push(DnType::CommonName, cn);

    // set it as CA
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let (start, end) = validity_period(VALIDITY_DAYS)?;

    params.not_before = start;
    params.not_after = end;

    Ok(params)
}

/// Generates certificate parameters for a leaf certificate with provided SANs
pub fn leaf_params(san: Vec<String>) -> Result<CertificateParams> {
    if san.is_empty() {
        return Err(anyhow!("SAN list cannot be empty"));
    }

    let mut params = CertificateParams::new(san.clone())?;
    params
        .distinguished_name
        .push(DnType::CommonName, san[0].clone());

    params.is_ca = IsCa::NoCa;

    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let (start, end) = validity_period(VALIDITY_DAYS)?;

    params.not_before = start;
    params.not_after = end;

    Ok(params)
}

/// generates root key and cert
pub fn generate_root_cert_and_key() -> Result<(KeyPair, Certificate)> {
    let params = root_params()?;
    let keypair = KeyPair::generate()?;
    let root_cert = params.self_signed(&keypair)?;
    Ok((keypair, root_cert))
}

/// Generates a leaf certificate and keypair signed by the provided root CA
pub fn generate_leaf_cert_and_key(
    san: Vec<String>,
    root_keypair: &KeyPair,
    root_cert_pem: &str,
) -> Result<(KeyPair, Certificate)> {
    let params = leaf_params(san)?;
    let leaf_keypair = KeyPair::generate()?;

    let issuer = Issuer::from_ca_cert_pem(root_cert_pem, root_keypair)?;

    let leaf_cert = params.signed_by(&leaf_keypair, &issuer)?;
    Ok((leaf_keypair, leaf_cert))
}

/// calculate validity period
pub fn validity_period(days: u32) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let day = Duration::new(86400, 0);
    let start = OffsetDateTime::now_utc()
        .checked_sub(day)
        .ok_or_else(|| anyhow::anyhow!("Failed to calculate start date"))?;
    let end = OffsetDateTime::now_utc()
        .checked_add(day * days)
        .ok_or_else(|| anyhow::anyhow!("Failed to calculate end date"))?;

    Ok((start, end))
}

/// Saves certificate or key content to a file based on the specified type
pub fn save(dir: &PathBuf, content: String, filetype: ZpkiType) -> Result<()> {
    let path = dir.join(filetype.filename());
    std::fs::write(path, content)?;
    Ok(())
}

/// Checks if root CA certificate and key files exist in the directory
pub fn is_root_exists(dir: &PathBuf) -> bool {
    dir.join(ROOT_KEY_FILENAME).exists() && dir.join(ROOT_CERT_FILENAME).exists()
}

/// Collects and merges SAN and IP arguments, returning subject name and combined list
pub fn collect_san_args(san: Vec<String>, ip: Vec<String>) -> Result<(String, Vec<String>)> {
    let mut san_inputs = san;
    san_inputs.extend(ip);

    let subject = san_inputs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("san or ip required"))?;

    Ok((subject, san_inputs))
}

/// Ensures root CA material exists by loading existing files or generating new ones
pub fn ensure_root_material(root_dir: &PathBuf) -> Result<(KeyPair, String)> {
    if is_root_exists(root_dir) {
        let root_key_pem = std::fs::read_to_string(root_dir.join(ROOT_KEY_FILENAME))?;
        let root_cert_pem = std::fs::read_to_string(root_dir.join(ROOT_CERT_FILENAME))?;
        let root_key = KeyPair::from_pem(&root_key_pem)?;
        Ok((root_key, root_cert_pem))
    } else {
        let (root_key, root_cert) = generate_root_cert_and_key()?;
        let root_cert_pem = root_cert.pem();

        save(root_dir, root_key.serialize_pem(), ZpkiType::RootKey)?;
        save(root_dir, root_cert_pem.clone(), ZpkiType::RootCert)?;

        Ok((root_key, root_cert_pem))
    }
}

#[cfg(test)]
mod tests {

    use rcgen::DnValue;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn check_san_root_params() {
        let params = root_params().unwrap();

        let dn = params.distinguished_name.get(&DnType::CommonName).unwrap();

        match dn {
            DnValue::Utf8String(s) => assert!(s.contains("ZPKI root ca")),
            _ => panic!("expected PrintableString variant containing IP address as string"),
        }
    }

    #[test]
    fn check_root_key_cert_saved_in_current_folder() {
        let (key, cert) = generate_root_cert_and_key().unwrap();

        let dir = tempdir().unwrap();
        let dir = PathBuf::from(dir.path());

        save(&dir, key.serialize_pem(), ZpkiType::RootKey).unwrap();
        save(&dir, cert.pem(), ZpkiType::RootCert).unwrap();

        let key_contents = std::fs::read_to_string(&dir.join("zpki-root-key.pem")).unwrap();
        let expected = key.serialize_pem();
        assert_eq!(key_contents, expected);

        let cert_contents = std::fs::read_to_string(&dir.join("zpki-root-cert.pem")).unwrap();
        let expected = cert.pem();
        assert_eq!(cert_contents, expected);
    }

    #[test]
    fn check_is_root_exists() {
        let (key, cert) = generate_root_cert_and_key().unwrap();

        let dir = tempdir().unwrap();
        let dir = PathBuf::from(dir.path());

        save(&dir, key.serialize_pem(), ZpkiType::RootKey).unwrap();
        save(&dir, cert.pem(), ZpkiType::RootCert).unwrap();

        let exists = is_root_exists(&dir);
        assert_eq!(exists, true);
    }
}
