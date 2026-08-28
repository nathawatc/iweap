use crate::model::{
    FileState, PlaintextProfile, Profile, TlsClientCredentials, ValidationError,
    profile_filename_for_ssid, validate_ssid,
};
use rustix::fs::{
    AtFlags, FileType, Gid, Mode, OFlags, RenameFlags, Uid, fchmod, fchown, fstat, fsync, mkdirat,
    open, openat, renameat, renameat_with, statat, unlinkat,
};
use rustix::process::geteuid;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const IWD_DIRECTORY: &str = "/var/lib/iwd";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum InstallError {
    Invalid(ValidationError),
    Io {
        operation: &'static str,
        detail: String,
    },
    DirectoryInsecure,
    UnexpectedDestination,
    ProfileAlreadyExists,
    StateChanged,
    InvalidReferencedFile,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => error.fmt(f),
            Self::Io { operation, detail } => write!(f, "{operation} failed: {detail}"),
            Self::DirectoryInsecure => {
                f.write_str("IWD state directory is not root-owned with mode 0700")
            }
            Self::UnexpectedDestination => {
                f.write_str("existing profile path is not a regular file")
            }
            Self::ProfileAlreadyExists => f.write_str("profile already exists"),
            Self::StateChanged => {
                f.write_str("profile state changed; inspect it again before replacing")
            }
            Self::InvalidReferencedFile => {
                f.write_str("certificate or private-key path is not an existing regular file")
            }
        }
    }
}

impl std::error::Error for InstallError {}

impl From<ValidationError> for InstallError {
    fn from(error: ValidationError) -> Self {
        Self::Invalid(error)
    }
}

pub struct Installer {
    root: PathBuf,
    require_root_owner: bool,
    set_owner: bool,
}

impl Installer {
    pub fn system() -> Self {
        Self {
            root: PathBuf::from(IWD_DIRECTORY),
            require_root_owner: true,
            set_owner: true,
        }
    }

    #[cfg(test)]
    fn for_test(root: PathBuf) -> Self {
        Self {
            root,
            require_root_owner: false,
            set_owner: false,
        }
    }

    pub fn inspect(&self, ssid: &str) -> Result<(String, FileState), InstallError> {
        validate_ssid(ssid)?;
        let filename = profile_filename_for_ssid(ssid);
        let Some(root_fd) = self.open_root(false, false, false)? else {
            return Ok((filename, FileState::absent()));
        };
        let state = self.read_state(&root_fd, &filename)?;
        Ok((filename, state))
    }

    pub fn install(
        &self,
        profile: &Profile,
        expected_state: FileState,
        overwrite: bool,
    ) -> Result<String, InstallError> {
        profile.validate()?;
        self.validate_referenced_files(profile)?;
        let filename = profile.profile_filename()?;
        let root_fd = self
            .open_root(true, true, true)?
            .ok_or_else(|| io_error("open state directory", "directory was not created"))?;
        let current_state = self.read_state(&root_fd, &filename)?;

        if current_state != expected_state {
            return Err(InstallError::StateChanged);
        }
        if current_state.exists && !overwrite {
            return Err(InstallError::ProfileAlreadyExists);
        }
        if !current_state.exists && overwrite {
            return Err(InstallError::StateChanged);
        }

        let plaintext = profile.serialize_plain()?;
        self.write_atomic(
            &root_fd,
            &filename,
            &plaintext,
            current_state,
            current_state.exists,
        )?;
        Ok(filename)
    }

    fn validate_referenced_files(&self, profile: &Profile) -> Result<(), InstallError> {
        for layer in &profile.layers {
            let Some(tls) = layer.tls.as_ref() else {
                continue;
            };
            if let Some(path) = tls.ca_cert.as_deref() {
                validate_referenced_file(path)?;
            }
            match &tls.client {
                TlsClientCredentials::None => {}
                TlsClientCredentials::CertificateAndKey { certificate, key } => {
                    validate_referenced_file(certificate)?;
                    validate_referenced_file(key)?;
                }
                TlsClientCredentials::Pkcs12 { bundle } => validate_referenced_file(bundle)?,
            }
        }
        Ok(())
    }

    fn open_root(
        &self,
        create: bool,
        repair_mode: bool,
        enforce_mode: bool,
    ) -> Result<Option<OwnedFd>, InstallError> {
        let parent = self
            .root
            .parent()
            .ok_or_else(|| io_error("resolve state directory", "missing parent"))?;
        let name = self
            .root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io_error("resolve state directory", "invalid directory name"))?;
        if !self.root.is_absolute() || name.is_empty() {
            return Err(io_error(
                "resolve state directory",
                "directory must be absolute",
            ));
        }

        let parent_fd = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error("open state parent", error))?;
        let root_fd = match openat(
            &parent_fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT && create => {
                let created = match mkdirat(&parent_fd, name, directory_mode()) {
                    Ok(()) => true,
                    Err(error) if error == rustix::io::Errno::EXIST => false,
                    Err(error) => return Err(io_error("create state directory", error)),
                };
                if created {
                    fsync(&parent_fd)
                        .map_err(|error| io_error("sync state parent directory", error))?;
                }
                openat(
                    &parent_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| io_error("open created state directory", error))?
            }
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(io_error("open state directory", error)),
        };

        let metadata =
            fstat(&root_fd).map_err(|error| io_error("inspect state directory", error))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(InstallError::DirectoryInsecure);
        }
        if self.require_root_owner && (metadata.st_uid != 0 || metadata.st_gid != 0) {
            return Err(InstallError::DirectoryInsecure);
        }
        if enforce_mode && Mode::from_raw_mode(metadata.st_mode) != directory_mode() {
            if !repair_mode {
                return Err(InstallError::DirectoryInsecure);
            }
            fchmod(&root_fd, directory_mode())
                .map_err(|error| io_error("restrict state directory", error))?;
        }
        if self.set_owner && (metadata.st_uid != 0 || metadata.st_gid != 0) {
            fchown(&root_fd, Some(Uid::ROOT), Some(Gid::ROOT))
                .map_err(|error| io_error("set state directory ownership", error))?;
            fchmod(&root_fd, directory_mode())
                .map_err(|error| io_error("restrict state directory", error))?;
        }
        Ok(Some(root_fd))
    }

    fn read_state(&self, root_fd: &OwnedFd, filename: &str) -> Result<FileState, InstallError> {
        let metadata = match statat(root_fd, filename, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(FileState::absent()),
            Err(error) => return Err(io_error("inspect profile", error)),
        };
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
            return Err(InstallError::UnexpectedDestination);
        }
        Ok(FileState {
            exists: true,
            device: metadata.st_dev,
            inode: metadata.st_ino,
            hard_links: metadata.st_nlink,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            size: metadata.st_size,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        })
    }

    fn write_atomic(
        &self,
        root_fd: &OwnedFd,
        filename: &str,
        plaintext: &PlaintextProfile,
        expected_state: FileState,
        replacing: bool,
    ) -> Result<(), InstallError> {
        let (temp_name, mut file) = self.open_temp(root_fd)?;
        let mut renamed = false;
        let result = (|| {
            file.write_all(plaintext.as_bytes())
                .map_err(|error| io_error("write profile", error))?;
            fchmod(&file, profile_mode()).map_err(|error| io_error("restrict profile", error))?;
            if self.set_owner {
                fchown(&file, Some(Uid::ROOT), Some(Gid::ROOT))
                    .map_err(|error| io_error("set profile ownership", error))?;
                fchmod(&file, profile_mode())
                    .map_err(|error| io_error("restrict profile", error))?;
            }
            file.sync_all()
                .map_err(|error| io_error("sync profile", error))?;
            drop(file);

            if self.read_state(root_fd, filename)? != expected_state {
                return Err(InstallError::StateChanged);
            }
            if replacing {
                renameat(root_fd, &temp_name, root_fd, filename)
                    .map_err(|error| io_error("replace profile", error))?;
            } else {
                renameat_with(
                    root_fd,
                    &temp_name,
                    root_fd,
                    filename,
                    RenameFlags::NOREPLACE,
                )
                .map_err(|error| io_error("create profile", error))?;
            }
            renamed = true;
            fsync(root_fd).map_err(|error| io_error("sync state directory", error))?;
            Ok(())
        })();
        if !renamed {
            let _ = unlinkat(root_fd, &temp_name, AtFlags::empty());
        }
        result
    }

    fn open_temp(&self, root_fd: &OwnedFd) -> Result<(String, File), InstallError> {
        for _ in 0..32 {
            let name = next_temp_name();
            match openat(
                root_fd,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                profile_mode(),
            ) {
                Ok(fd) => return Ok((name, File::from(fd))),
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(io_error("create temporary profile", error)),
            }
        }
        Err(io_error("create temporary profile", "name collision"))
    }
}

fn validate_referenced_file(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::metadata(path).map_err(|_| InstallError::InvalidReferencedFile)?;
    if !metadata.is_file() {
        return Err(InstallError::InvalidReferencedFile);
    }
    Ok(())
}

fn directory_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::XUSR
}

fn profile_mode() -> Mode {
    Mode::RUSR | Mode::WUSR
}

fn next_temp_name() -> String {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(
        ".iweap-{timestamp:x}-{pid:x}-{sequence:x}.tmp",
        pid = std::process::id()
    )
}

fn io_error(operation: &'static str, error: impl std::fmt::Display) -> InstallError {
    InstallError::Io {
        operation,
        detail: error.to_string(),
    }
}

pub fn running_as_root() -> bool {
    geteuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EapLayer, EapMethod, Secret};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        parent: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let parent = std::env::temp_dir().join(format!(
                "iweap-filesystem-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&parent).expect("create test fixture");
            Self {
                root: parent.join("iwd"),
                parent,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    fn profile(password: &str) -> Profile {
        let mut layer = EapLayer::new(EapMethod::Mschapv2);
        layer.identity = Some(String::from("user"));
        layer.password = Some(Secret::new(password));
        Profile::new(String::from("Office Wi-Fi"), vec![layer])
    }

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.expect("test operation")
    }

    #[test]
    fn fresh_install_is_private_and_inspectable() {
        let fixture = Fixture::new();
        let installer = Installer::for_test(fixture.root.clone());
        let profile = profile("first-secret");

        let filename = ok(installer.install(&profile, FileState::absent(), false));
        assert_eq!(filename, "Office Wi-Fi.8021x");
        assert_eq!(
            fs::metadata(&fixture.root)
                .expect("state directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(fixture.root.join(&filename))
                .expect("profile")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let stored = fs::read(fixture.root.join(&filename)).expect("profile contents");
        let expected = profile.serialize_plain().expect("serialized profile");
        assert!(stored == expected.as_bytes());
        let (inspected_filename, state) = ok(installer.inspect(&profile.ssid));
        assert_eq!(inspected_filename, filename);
        assert!(state.exists);
        assert_eq!(state.mode & 0o777, 0o600);
    }

    #[test]
    fn overwrite_requires_current_state_and_preserves_hardlink_target() {
        let fixture = Fixture::new();
        let installer = Installer::for_test(fixture.root.clone());
        let first = profile("first-secret");
        let second = profile("second-secret");
        let filename = ok(installer.install(&first, FileState::absent(), false));
        let path = fixture.root.join(&filename);
        let other_link = fixture.parent.join("other-link");
        fs::hard_link(&path, &other_link).expect("create hard link");
        let (_, state) = ok(installer.inspect(&first.ssid));

        assert!(matches!(
            installer.install(&second, state, false),
            Err(InstallError::ProfileAlreadyExists)
        ));
        let stale = FileState::absent();
        assert!(matches!(
            installer.install(&second, stale, true),
            Err(InstallError::StateChanged)
        ));
        ok(installer.install(&second, state, true));
        let first_contents = first.serialize_plain().expect("first profile");
        let second_contents = second.serialize_plain().expect("second profile");
        assert!(fs::read(&other_link).expect("hardlink contents") == first_contents.as_bytes());
        assert!(fs::read(&path).expect("replaced profile") == second_contents.as_bytes());
    }

    #[test]
    fn symlink_destination_is_never_accepted() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).expect("create state directory");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        let filename = profile("secret").profile_filename().expect("filename");
        symlink("missing-target", fixture.root.join(filename)).expect("create symlink");
        let installer = Installer::for_test(fixture.root.clone());

        assert!(matches!(
            installer.inspect("Office Wi-Fi"),
            Err(InstallError::UnexpectedDestination)
        ));
    }

    #[test]
    fn directory_destination_is_never_accepted() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).expect("create state directory");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        let filename = profile("secret").profile_filename().expect("filename");
        fs::create_dir(fixture.root.join(filename)).expect("create directory destination");
        let installer = Installer::for_test(fixture.root.clone());

        assert!(matches!(
            installer.inspect("Office Wi-Fi"),
            Err(InstallError::UnexpectedDestination)
        ));
    }

    #[test]
    fn special_destination_is_never_accepted() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).expect("create state directory");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        let filename = profile("secret").profile_filename().expect("filename");
        let _socket = UnixListener::bind(fixture.root.join(filename)).expect("create socket");
        let installer = Installer::for_test(fixture.root.clone());

        assert!(matches!(
            installer.inspect("Office Wi-Fi"),
            Err(InstallError::UnexpectedDestination)
        ));
    }

    #[test]
    fn install_repairs_fixture_directory_mode() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).expect("create state directory");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755))
            .expect("set loose mode");
        let installer = Installer::for_test(fixture.root.clone());

        let (_, state) = ok(installer.inspect("Office Wi-Fi"));
        assert!(!state.exists);
        assert_eq!(
            fs::metadata(&fixture.root)
                .expect("state directory")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        ok(installer.install(&profile("secret"), FileState::absent(), false));
        assert_eq!(
            fs::metadata(&fixture.root)
                .expect("state directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
