use std::fs;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use lru::LruCache;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

const CERT_FILE: &str = "sluice-ca.pem";
const KEY_FILE: &str = "sluice-ca.key";
const LEAF_KEY_FILE: &str = "sluice-leaf.key";
const CACHE_SIZE: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The per-install root certificate and a cache of per-host server configs.
pub struct CertAuthority {
    cert: Certificate,
    key: KeyPair,
    /// Shared by every per-host certificate, so a browser can be told to
    /// trust one fingerprint instead of needing a certificate store.
    leaf_key: KeyPair,
    cert_pem: String,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// Loads the CA from `dir`, generating and saving one on first use.
    pub fn load_or_create(dir: &Path) -> Result<Self, CaError> {
        fs::create_dir_all(dir)?;
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let leaf_key = load_or_generate_key(&dir.join(LEAF_KEY_FILE))?;
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key = KeyPair::from_pem(&fs::read_to_string(&key_path)?)?;
            let cert = CertificateParams::from_ca_cert_pem(&cert_pem)?.self_signed(&key)?;
            return Ok(Self::from_parts(cert, key, leaf_key, cert_pem));
        }
        let key = KeyPair::generate()?;
        let cert = root_params().self_signed(&key)?;
        let cert_pem = cert.pem();
        write_private(&key_path, key.serialize_pem().as_bytes())?;
        fs::write(&cert_path, &cert_pem)?;
        Ok(Self::from_parts(cert, key, leaf_key, cert_pem))
    }

    fn from_parts(cert: Certificate, key: KeyPair, leaf_key: KeyPair, cert_pem: String) -> Self {
        let size = NonZeroUsize::new(CACHE_SIZE).expect("cache size is non-zero");
        Self {
            cert,
            key,
            leaf_key,
            cert_pem,
            cache: Mutex::new(LruCache::new(size)),
        }
    }

    /// The public certificate, for installing in a browser's trust store.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The saved root certificate as base64 DER, exactly as it was exported.
    pub fn cert_base64(&self) -> String {
        self.cert_pem.lines().filter(|line| !line.starts_with("-----")).collect()
    }

    /// Base64 SHA-256 of the per-host public key, in the form Chrome expects.
    pub fn leaf_spki_base64(&self) -> String {
        BASE64.encode(Sha256::digest(self.leaf_key.public_key_der()))
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let key = host.to_ascii_lowercase();
        if let Some(config) = self.cache.lock().expect("cache lock").get(&key) {
            return Ok(config.clone());
        }
        let config = Arc::new(self.issue(&key)?);
        self.cache.lock().expect("cache lock").put(key, config.clone());
        Ok(config)
    }

    fn issue(&self, host: &str) -> Result<ServerConfig, CaError> {
        let leaf = leaf_params(host)?.signed_by(&self.leaf_key, &self.cert, &self.key)?;
        let private = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], private)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn root_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Sluice Local CA");
    name.push(DnType::OrganizationName, "Sluice");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    params
}

/// rcgen derives a default serial from the public key, which would give every
/// certificate the same one here. Firefox rejects a repeated issuer and serial.
fn unique_serial(host: &str) -> SerialNumber {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let digest = Sha256::new()
        .chain_update(host)
        .chain_update(OffsetDateTime::now_utc().unix_timestamp_nanos().to_be_bytes())
        .chain_update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes())
        .finalize();
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&digest[..16]);
    // Serials must be positive and non-zero.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    SerialNumber::from_slice(&serial)
}

fn leaf_params(host: &str) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, host);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.serial_number = Some(unique_serial(host));
    // Browsers reject leaf certificates valid for longer than 397 days.
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365);
    Ok(params)
}

fn load_or_generate_key(path: &Path) -> Result<KeyPair, CaError> {
    if path.exists() {
        return Ok(KeyPair::from_pem(&fs::read_to_string(path)?)?);
    }
    let key = KeyPair::generate()?;
    write_private(path, key.serialize_pem().as_bytes())?;
    Ok(key)
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_persists_between_loads() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertAuthority::load_or_create(dir.path()).unwrap();
        let second = CertAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
    }

    #[test]
    fn every_certificate_gets_its_own_serial() {
        let serial = |host| leaf_params(host).unwrap().serial_number.unwrap();
        assert_ne!(serial("a.test"), serial("b.test"));
        assert_ne!(serial("a.test"), serial("a.test"));
    }

    #[test]
    fn leaf_fingerprint_survives_reloading() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertAuthority::load_or_create(dir.path()).unwrap();
        let second = CertAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(first.leaf_spki_base64(), second.leaf_spki_base64());
        // 32 bytes of SHA-256 is 44 characters of padded base64.
        assert_eq!(first.leaf_spki_base64().len(), 44);
    }

    #[test]
    fn cert_base64_is_the_saved_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::load_or_create(dir.path()).unwrap();
        let encoded = ca.cert_base64();
        assert!(ca.cert_pem().contains(&encoded[..60]));
        assert!(!encoded.contains('-') && !encoded.contains('\n'));
    }

    #[cfg(unix)]
    #[test]
    fn private_keys_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        CertAuthority::load_or_create(dir.path()).unwrap();
        for file in [KEY_FILE, LEAF_KEY_FILE] {
            let mode = fs::metadata(dir.path().join(file)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    #[test]
    fn host_configs_are_cached_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::load_or_create(dir.path()).unwrap();
        let a = ca.server_config("a.test").unwrap();
        let b = ca.server_config("A.TEST").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        ca.server_config("127.0.0.1").unwrap();
    }
}
