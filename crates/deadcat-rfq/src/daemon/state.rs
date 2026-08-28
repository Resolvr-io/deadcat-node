use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use deadcat_rfq_iroh::SecretKey;
use deadcat_rfq_provider::{ProviderId, ProviderIdentity};
use deadcat_types::LiquidNetwork;
use elements::{AssetId, BlockHash};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

pub(super) const MANIFEST_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 4 * 1024;

const IROH_SECRET_FILE: &str = "iroh-secret";
const WALLET_FILE: &str = "wallet.redb";
const PROVIDER_FILE: &str = "provider.redb";
const MANIFEST_FILE: &str = "manifest.json";

#[derive(Clone, Debug)]
pub(super) struct StatePaths {
    pub(super) directory: PathBuf,
    pub(super) iroh_secret: PathBuf,
    pub(super) wallet: PathBuf,
    pub(super) provider: PathBuf,
    pub(super) manifest: PathBuf,
}

impl StatePaths {
    pub(super) fn new(directory: PathBuf) -> Self {
        Self {
            iroh_secret: directory.join(IROH_SECRET_FILE),
            wallet: directory.join(WALLET_FILE),
            provider: directory.join(PROVIDER_FILE),
            manifest: directory.join(MANIFEST_FILE),
            directory,
        }
    }

    pub(super) fn require_uninitialized(&self) -> anyhow::Result<()> {
        for path in [
            &self.iroh_secret,
            &self.wallet,
            &self.provider,
            &self.manifest,
        ] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Ok(_) => bail!(
                    "RFQ state target {} already exists; initialization never overwrites or resumes partial state",
                    path.display()
                ),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect RFQ state target {}", path.display()));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderManifest {
    pub(super) schema_version: u32,
    #[serde(with = "hex::serde")]
    pub(super) provider_id: [u8; 32],
    pub(super) network: LiquidNetwork,
    pub(super) genesis_hash: BlockHash,
    pub(super) policy_asset: AssetId,
}

impl ProviderManifest {
    pub(super) fn new(identity: ProviderIdentity, network: LiquidNetwork) -> Self {
        Self {
            schema_version: MANIFEST_VERSION,
            provider_id: identity.provider().to_bytes(),
            network,
            genesis_hash: identity.genesis_hash(),
            policy_asset: identity.policy_asset(),
        }
    }

    pub(super) fn identity(&self) -> anyhow::Result<ProviderIdentity> {
        if self.schema_version != MANIFEST_VERSION {
            bail!(
                "unsupported RFQ state manifest version {}; expected {MANIFEST_VERSION}",
                self.schema_version
            );
        }
        Ok(ProviderIdentity::new(
            ProviderId::new(self.provider_id),
            self.genesis_hash,
            self.policy_asset,
        ))
    }
}

pub(super) fn create_state_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => sync_parent(path)?,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create RFQ state directory {}", path.display()));
            }
        }
        validate_state_directory(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("the persistent RFQ daemon is currently supported only on Unix")
    }
}

pub(super) fn validate_state_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect RFQ state directory {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            bail!("RFQ state path {} is not a real directory", path.display());
        }
        let expected_owner = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_owner {
            bail!(
                "RFQ state directory {} is owned by uid {}, expected {}",
                path.display(),
                metadata.uid(),
                expected_owner
            );
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!(
                "RFQ state directory {} must have mode 0700, found {mode:#o}",
                path.display()
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("the persistent RFQ daemon is currently supported only on Unix")
    }
}

pub(super) fn read_config<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = read_bounded_file(path, MAX_CONFIG_BYTES, FilePolicy::Config)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse RFQ configuration {}", path.display()))
}

pub(super) fn read_passphrase(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(read_bounded_file(
        path,
        MAX_PASSPHRASE_BYTES,
        FilePolicy::Private,
    )?);
    if bytes.ends_with(b"\r\n") {
        let new_length = bytes.len() - 2;
        bytes.truncate(new_length);
    } else if bytes.ends_with(b"\n") {
        let new_length = bytes.len() - 1;
        bytes.truncate(new_length);
    }
    if bytes.is_empty() {
        bail!("wallet passphrase file is empty");
    }
    if bytes.contains(&0) {
        bail!("wallet passphrase file contains a NUL byte");
    }
    Ok(bytes)
}

pub(super) fn load_iroh_secret(path: &Path) -> anyhow::Result<SecretKey> {
    let bytes = Zeroizing::new(read_bounded_file(path, 32, FilePolicy::Private)?);
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()))?;
    Ok(SecretKey::from_bytes(&bytes))
}

pub(super) fn create_iroh_secret(path: &Path) -> anyhow::Result<SecretKey> {
    let secret = SecretKey::generate();
    write_new_private(path, &secret.to_bytes())?;
    Ok(secret)
}

pub(super) fn load_manifest(path: &Path) -> anyhow::Result<ProviderManifest> {
    let bytes = read_bounded_file(path, MAX_MANIFEST_BYTES, FilePolicy::Private)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse RFQ state manifest {}", path.display()))
}

pub(super) fn write_manifest(path: &Path, manifest: &ProviderManifest) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest).context("serialize RFQ state manifest")?;
    write_new_private(path, &bytes)
}

pub(super) fn validate_private_file(path: &Path) -> anyhow::Result<()> {
    let _ = open_checked(path, FilePolicy::Private)?;
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: usize, policy: FilePolicy) -> anyhow::Result<Vec<u8>> {
    let mut file = open_checked(path, policy)?;
    let limit = u64::try_from(maximum)
        .expect("usize fits u64 on supported Unix targets")
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(8 * 1024));
    std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{} exceeds the {maximum}-byte limit", path.display());
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Config,
    Private,
}

fn open_checked(path: &Path, policy: FilePolicy) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        validate_open_file(path, &file, policy)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, policy);
        bail!("the persistent RFQ daemon is currently supported only on Unix")
    }
}

#[cfg(unix)]
fn validate_open_file(path: &Path, file: &File, policy: FilePolicy) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let expected_owner = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_owner {
        bail!(
            "{} is owned by uid {}, expected {}",
            path.display(),
            metadata.uid(),
            expected_owner
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    match policy {
        FilePolicy::Private if mode != 0o600 => {
            bail!("{} must have mode 0600, found {mode:#o}", path.display())
        }
        FilePolicy::Config if mode & 0o022 != 0 => bail!(
            "{} must not be group- or world-writable, found {mode:#o}",
            path.display()
        ),
        _ => Ok(()),
    }
}

fn write_new_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(path).with_context(|| {
            format!(
                "create {} without replacing an existing file",
                path.display()
            )
        })?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", path.display()))?;
        validate_open_file(path, &file, FilePolicy::Private)?;
        sync_parent(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        bail!("the persistent RFQ daemon is currently supported only on Unix")
    }
}

fn sync_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync parent directory {}", parent.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use elements::hashes::Hash as _;
    use tempfile::TempDir;

    use super::*;

    fn secure_dir() -> TempDir {
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        temporary
    }

    #[test]
    fn creates_and_reloads_one_stable_secret_without_clobber() {
        let temporary = secure_dir();
        let path = temporary.path().join(IROH_SECRET_FILE);
        let created = create_iroh_secret(&path).expect("create secret");
        let loaded = load_iroh_secret(&path).expect("load secret");
        assert_eq!(created.public(), loaded.public());
        assert!(create_iroh_secret(&path).is_err());
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn private_reads_reject_insecure_modes_and_symlinks() {
        let temporary = secure_dir();
        let target = temporary.path().join("target");
        write_new_private(&target, &[7; 32]).expect("private target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("change mode");
        assert!(load_iroh_secret(&target).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("restore mode");
        let alias = temporary.path().join("alias");
        symlink(&target, &alias).expect("symlink");
        assert!(load_iroh_secret(&alias).is_err());
    }

    #[test]
    fn passphrase_removes_only_one_line_ending_and_rejects_invalid_bytes() {
        let temporary = secure_dir();
        let path = temporary.path().join("passphrase");
        write_new_private(&path, b"  meaningful spaces  \r\n").expect("passphrase");
        assert_eq!(
            read_passphrase(&path).expect("read passphrase").as_slice(),
            b"  meaningful spaces  "
        );

        let invalid = temporary.path().join("invalid");
        write_new_private(&invalid, b"bad\0secret").expect("invalid passphrase");
        assert!(read_passphrase(&invalid).is_err());
    }

    #[test]
    fn state_directory_is_exactly_private() {
        let temporary = secure_dir();
        let state = temporary.path().join("state");
        create_state_directory(&state).expect("create state directory");
        assert_eq!(
            fs::metadata(&state).expect("metadata").permissions().mode() & 0o777,
            0o700
        );
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).expect("change mode");
        assert!(validate_state_directory(&state).is_err());
    }

    #[test]
    fn manifest_is_private_strict_and_identity_bound() {
        let temporary = secure_dir();
        let path = temporary.path().join(MANIFEST_FILE);
        let identity = ProviderIdentity::new(
            ProviderId::new([7; 32]),
            BlockHash::from_byte_array([8; 32]),
            AssetId::from_byte_array([9; 32]),
        );
        let manifest = ProviderManifest::new(identity, LiquidNetwork::ElementsRegtest);
        write_manifest(&path, &manifest).expect("write manifest");
        let loaded = load_manifest(&path).expect("load manifest");
        assert_eq!(loaded, manifest);
        assert_eq!(loaded.identity().expect("identity"), identity);
        assert!(write_manifest(&path, &manifest).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("widen manifest permissions");
        assert!(load_manifest(&path).is_err());
    }

    #[test]
    fn initialization_never_resumes_a_partial_state_set() {
        let temporary = secure_dir();
        let paths = StatePaths::new(temporary.path().to_path_buf());
        paths.require_uninitialized().expect("initially empty");
        write_new_private(&paths.iroh_secret, &[1; 32]).expect("partial identity");
        assert!(paths.require_uninitialized().is_err());
        assert!(!paths.wallet.exists());
        assert!(!paths.provider.exists());
        assert!(!paths.manifest.exists());
    }
}
