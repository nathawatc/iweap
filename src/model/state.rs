use super::wire::WireProfile;
use serde::{Deserialize, Serialize};
use zvariant::Type;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
pub struct FileState {
    pub exists: bool,
    pub device: u64,
    pub inode: u64,
    pub hard_links: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: u64,
}

impl FileState {
    pub const fn absent() -> Self {
        Self {
            exists: false,
            device: 0,
            inode: 0,
            hard_links: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct ProfileInspection {
    pub filename: String,
    pub state: FileState,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct InstallRequest {
    pub profile: WireProfile,
    pub expected_state: FileState,
    pub overwrite: bool,
}
