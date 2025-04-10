use base64::prelude::*;
use chrono::{NaiveDateTime, Utc};
use easy_fuser::prelude::*;
use easy_fuser::templates::fd_handler_helper::FdHandlerHelper;
use easy_fuser::{FuseHandler, templates::DefaultFuseHandler};
use reqwest::{Client, Error, IntoUrl, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::u64;
use thiserror::Error;
use tokio::runtime::Runtime;

struct NeptisFS {
    inner_fs: DefaultFuseHandler,
    client: Client,
    auth: Arc<Mutex<Option<AuthOutput>>>,
    base_url: String,
    user: String,
    password: String,
    rt: Runtime,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeDto {
    pub path: String,
    pub atime: SystemTime,
    pub ctime: SystemTime,
    pub mtime: SystemTime,
    pub is_dir: bool,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthOutput {
    pub token: String,
    pub expire_date: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeekPos {
    Start(u64),
    End(i64),
    Current(i64),
}

impl From<SeekPos> for std::io::SeekFrom {
    fn from(pos: SeekPos) -> Self {
        match pos {
            SeekPos::Start(n) => std::io::SeekFrom::Start(n),
            SeekPos::End(n) => std::io::SeekFrom::End(n),
            SeekPos::Current(n) => std::io::SeekFrom::Current(n),
        }
    }
}

impl From<SeekFrom> for SeekPos {
    fn from(pos: SeekFrom) -> Self {
        match pos {
            SeekFrom::Start(n) => SeekPos::Start(n),
            SeekFrom::End(n) => SeekPos::End(n),
            SeekFrom::Current(n) => SeekPos::Current(n),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetForDumpApi {
    pub path: String,
    pub offset: SeekPos,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum TimeOrNow {
    /// Specific time provided
    SpecificTime(SystemTime),
    /// Current time
    Now,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SetAttrRequest {
    /// File size in bytes
    pub size: Option<u64>,
    /// Last access time
    pub atime: Option<TimeOrNow>,
    /// Last modification time
    pub mtime: Option<TimeOrNow>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PutForFileApi {
    pub path: String,
    pub base64: Option<String>,
    pub new_path: Option<String>,
    pub offset: Option<SeekPos>,
    pub attr: Option<SetAttrRequest>,
}

#[derive(Serialize, Deserialize)]
pub struct PostForFileApi {
    pub path: String,
    pub is_dir: bool,
    pub base64: Option<String>,
    pub offset: Option<SeekPos>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PutForXattrApi {
    pub path: String,
    pub key: String,
    pub base64: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeleteForXattrApi {
    pub path: String,
    pub key: String,
}

#[derive(Serialize, Deserialize)]
pub struct MountDto {
    pub name: String,
    pub owned_by: String,
    pub data_max_bytes: i64,
    pub repo_max_bytes: i64,
    pub data_used_bytes: Option<i64>,
    pub repo_used_bytes: Option<i64>,
    pub date_created: NaiveDateTime,
    pub data_accessed: NaiveDateTime,
    pub repo_accessed: NaiveDateTime,
}

#[derive(Error, Debug)]
enum NeptisError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    InternalError(String),

    #[error(transparent)]
    Decode(#[from] base64::DecodeError),
}

const BLOCK_SIZE: u64 = 4096;

impl NeptisFS {
    async fn ensure_auth(&self) -> Result<String, NeptisError> {
        let mut f_auth = self.auth.lock().unwrap();

        if f_auth
            .as_ref()
            .is_none_or(|x| Utc::now().naive_utc() >= x.expire_date)
        {
            *f_auth = None; // set to none on the event of errors - it will try again!
            let mut map = HashMap::new();
            map.insert("user_name", self.user.as_str());
            map.insert("password", self.password.as_str());

            *f_auth = Some(
                self.client
                    .post(format!("{}/users/auth", self.base_url.as_str()))
                    .json(&map)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?,
            );
        }
        Ok(f_auth
            .as_ref()
            .map(|x| x.token.clone())
            .ok_or(NeptisError::InternalError("Failed to find auth!".into()))?)
    }

    pub fn new(
        base_url: impl IntoUrl,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<NeptisFS, NeptisError> {
        // Attempt to login to the server.
        Ok(Self {
            inner_fs: DefaultFuseHandler::new(),
            auth: Arc::new(Mutex::new(None)),
            base_url: base_url.as_str().to_string(),
            user: user.into(),
            password: password.into(),
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            rt: tokio::runtime::Runtime::new().unwrap(),
        })
    }

    pub async fn get_files(&self, path: impl Into<String>) -> Result<Vec<NodeDto>, NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .get(format!("{}/mounts/browse", self.base_url.as_str()))
            .body(path.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<NodeDto>>()
            .await?)
    }

    pub async fn get_xattrs(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<(String, Vec<u8>)>, NeptisError> {
        let token = self.ensure_auth().await?;
        let p_string = path.into();
        Ok(self
            .client
            .get(format!("{}/mounts/xattrs", self.base_url.as_str()))
            .body(p_string)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<PutForXattrApi>>()
            .await?
            .iter()
            .map(|x| {
                (
                    x.key.clone(),
                    BASE64_STANDARD.decode(x.base64.as_str()).ok(),
                )
            })
            .filter_map(|(key, val)| val.map(|y| (key, y)))
            .collect::<Vec<_>>())
    }

    pub async fn dump_file(&self, dto: impl Into<GetForDumpApi>) -> Result<Vec<u8>, NeptisError> {
        let token = self.ensure_auth().await?;
        self.client
            .get(format!("{}/mounts/dump", self.base_url.as_str()))
            .json(&dto.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
            .map(|x| Ok(BASE64_STANDARD.decode(x)?))?
    }

    pub async fn delete_file(&self, path: impl Into<String>) -> Result<(), NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .delete(format!("{}/mounts/file", self.base_url.as_str()))
            .body(path.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()
            .map(|_| ())?)
    }

    pub async fn put_file(&self, dto: impl Into<PutForFileApi>) -> Result<(), NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .put(format!("{}/mounts/file", self.base_url.as_str()))
            .json(&dto.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()
            .map(|_| ())?)
    }

    pub async fn post_file(&self, dto: impl Into<PostForFileApi>) -> Result<(), NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .post(format!("{}/mounts/file", self.base_url.as_str()))
            .json(&dto.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()
            .map(|_| ())?)
    }

    pub async fn put_xattr(&self, dto: impl Into<PutForXattrApi>) -> Result<(), NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .post(format!("{}/mounts/xattrs", self.base_url.as_str()))
            .json(&dto.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()
            .map(|_| ())?)
    }

    pub async fn delete_xattr(&self, dto: impl Into<DeleteForXattrApi>) -> Result<(), NeptisError> {
        let token = self.ensure_auth().await?;
        Ok(self
            .client
            .delete(format!("{}/mounts/xattrs", self.base_url.as_str()))
            .json(&dto.into())
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()
            .map(|_| ())?)
    }

    pub async fn get_fs_info(&self, path: impl Into<String>) -> Result<StatFs, NeptisError> {
        let token = self.ensure_auth().await?;
        let mut f_path = path.into().to_string();
        f_path = f_path
            .strip_suffix("/")
            .unwrap_or(f_path.as_str())
            .to_string();

        let ret = self
            .client
            .get(format!("{}/mounts", self.base_url.as_str()))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<MountDto>>()
            .await?;

        let mut total_max_bytes = 0;
        let mut total_used_bytes = 0;
        if f_path.is_empty() {
            // The path is empty - we just need to sum for everything!
            for x in ret {
                total_max_bytes += x.data_max_bytes as usize;
                total_max_bytes += x.repo_max_bytes as usize;
                total_used_bytes += x.data_used_bytes.unwrap_or(0) as usize;
                total_used_bytes += x.repo_used_bytes.unwrap_or(0) as usize;
            }
        } else {
            let (s1, s2) = f_path
                .split_once("/")
                .map(|x| if x.0.is_empty() { None } else { Some(x) })
                .ok_or(NeptisError::InternalError("Failed to split path".into()))?
                .ok_or(NeptisError::InternalError("Name is blank!".into()))?;

            let mut is_data = s2.starts_with("data");
            let mut is_repo = s2.starts_with("repo");
            if !is_data && !is_repo {
                is_data = true;
                is_repo = true;
            }

            let point = ret
                .iter()
                .find(|x| x.name == s1)
                .ok_or(NeptisError::InternalError("Invalid path!".into()))?;
            if is_data {
                total_max_bytes += point.data_max_bytes as usize;
                total_used_bytes += point.data_used_bytes.unwrap_or(0) as usize;
            }
            if is_repo {
                total_max_bytes += point.repo_max_bytes as usize;
                total_used_bytes += point.repo_used_bytes.unwrap_or(0) as usize;
            }
        }
        Ok(StatFs {
            total_blocks: total_max_bytes as u64 / BLOCK_SIZE,
            free_blocks: total_max_bytes.saturating_sub(total_used_bytes) as u64 / BLOCK_SIZE,
            available_blocks: total_max_bytes.saturating_sub(total_used_bytes) as u64 / BLOCK_SIZE,
            total_files: u64::MAX,
            free_files: u64::MAX,
            block_size: BLOCK_SIZE as u32,
            max_filename_length: 255,
            fragment_size: BLOCK_SIZE as u32,
        })
    }

    // fn get_level(path: impl Into<String>) -> usize {
    //     let mut str: String = path.into();
    //     str = str.strip_prefix("/").unwrap_or(str.as_str()).to_string();
    //     str = str.strip_suffix("/").unwrap_or(str.as_str()).to_string();
    //     str.trim().to_string().chars().filter(|x| *x == '/').count()
    // }

    fn get_level(path: &str) -> usize {
        // Trim any leading or trailing '/' characters.
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            0
        } else {
            // Split into components and count them.
            let y = trimmed.split('/').count();
            return y;
        }
    }

    fn into_attr(x: NodeDto) -> FileAttribute {
        FileAttribute {
            size: x.bytes,
            blocks: (x.bytes / 4096).min(1),
            atime: x.atime,
            mtime: x.mtime,
            ctime: x.ctime,
            crtime: x.ctime,
            kind: if x.is_dir {
                FileKind::Directory
            } else {
                FileKind::RegularFile
            },
            perm: 0o777,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            flags: 0,
            blksize: 4096,
            ttl: None,
            generation: None,
        }
    }

    pub fn get_root_attribute() -> FileAttribute {
        FileAttribute {
            size: 0,
            blocks: 0,
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind: FileKind::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            flags: 0,
            blksize: 512,
            ttl: None,
            generation: None,
        }
    }

    fn do_lookup(&self, file_id: impl Into<String>) -> Result<FileAttribute, PosixError> {
        self.rt.block_on(async {
            let mut f_path = file_id.into();
            if !f_path.starts_with("/") {
                f_path = format!("/{}", f_path);
            }
            println!("Attempting to lookup {}", f_path);
            let ret: Option<FileAttribute> = self
                .get_files(f_path.as_str())
                .await
                .ok()
                .ok_or(PosixError::new(
                    ErrorKind::NetworkUnreachable,
                    "Failed to reach network.",
                ))?
                .into_iter()
                .find(|x| x.path == f_path.as_str())
                .map(Self::into_attr);
            match ret {
                Some(x) => Ok(x),
                None => Err(PosixError::new(ErrorKind::FileNotFound, "File not found.")),
            }
        })
    }

    fn do_delete_node(&self, path: impl Into<String>) -> Result<(), PosixError> {
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with("/") {
                f_path = format!("/{}", f_path);
            }
            self.delete_file(f_path).await.ok().ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })
    }

    fn do_create_node(
        &self,
        path: impl Into<String>,
        is_dir: impl Into<bool>,
    ) -> Result<FileAttribute, PosixError> {
        let mut f_path = path.into();
        if !f_path.starts_with("/") {
            f_path = format!("/{}", f_path);
        }
        self.rt.block_on(async {
            self.post_file(PostForFileApi {
                path: f_path.clone().into(),
                is_dir: is_dir.into(),
                base64: None,
                offset: None,
            })
            .await
            .ok()
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })?;
        self.do_lookup(f_path.as_str())
    }

    fn do_rename(
        &self,
        path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), PosixError> {
        self.rt.block_on(async {
            let mut f1_path = path.into();
            let mut f2_path = new_path.into();
            if !f1_path.starts_with("/") {
                f1_path = format!("/{}", f1_path);
            }
            if !f2_path.starts_with("/") {
                f2_path = format!("/{}", f2_path);
            }
            self.put_file(PutForFileApi {
                path: f1_path,
                new_path: Some(f2_path),
                base64: None,
                offset: None,
                attr: None,
            })
            .await
            .ok()
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })
    }

    fn do_setattr(
        &self,
        path: impl Into<String>,
        req: SetAttrRequest,
    ) -> Result<FileAttribute, PosixError> {
        let mut f_path = path.into();
        if !f_path.starts_with("/") {
            f_path = format!("/{}", f_path);
        }
        self.rt.block_on(async {
            self.put_file(PutForFileApi {
                path: f_path.clone().into(),
                new_path: None,
                base64: None,
                offset: None,
                attr: Some(req),
            })
            .await
            .ok()
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })?;
        self.do_lookup(f_path.as_str())
    }

    fn do_write(
        &self,
        path: impl Into<String>,
        bytes: Vec<u8>,
        seek: SeekFrom,
    ) -> Result<u32, PosixError> {
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with("/") {
                f_path = format!("/{}", f_path);
            }
            self.put_file(PutForFileApi {
                path: f_path,
                new_path: None,
                offset: Some(seek.into()),
                base64: Some(BASE64_STANDARD.encode(bytes.as_slice())),
                attr: None,
            })
            .await
            .ok()
            .map(|_| bytes.len() as u32)
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })
    }

    fn do_statfs(&self, path: impl Into<String>) -> Result<StatFs, PosixError> {
        self.rt.block_on(async {
            self.get_fs_info(path.into())
                .await
                .ok()
                .ok_or(PosixError::new(
                    ErrorKind::NetworkUnreachable,
                    "Failed to reach network.",
                ))
        })
    }

    fn do_setxattr(
        &self,
        path: impl Into<String>,
        key: impl Into<String>,
        val: impl AsRef<[u8]>,
    ) -> Result<(), PosixError> {
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with("/") {
                f_path = format!("/{}", f_path);
            }
            if f_path.chars().filter(|x| *x == '/').count() <= 1 {
                return Err(PosixError::new(
                    ErrorKind::FunctionNotImplemented,
                    "Not implemented",
                ));
            }
            self.put_xattr(PutForXattrApi {
                path: f_path,
                key: key.into(),
                base64: BASE64_STANDARD.encode(val),
            })
            .await
            .ok()
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })
    }

    fn do_delxattr(
        &self,
        path: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<(), PosixError> {
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with("/") {
                f_path = format!("/{}", f_path);
            }
            if f_path.chars().filter(|x| *x == '/').count() <= 1 {
                return Err(PosixError::new(
                    ErrorKind::FunctionNotImplemented,
                    "Not implemented",
                ));
            }
            self.delete_xattr(DeleteForXattrApi {
                path: f_path,
                key: key.into(),
            })
            .await
            .ok()
            .ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))
        })
    }

    fn do_listxattr(&self, path: impl Into<String>, size: u32) -> Result<Vec<u8>, PosixError> {
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with('/') {
                f_path = format!("/{}", f_path);
            }
            if f_path.chars().filter(|x| *x == '/').count() <= 1 {
                return Err(PosixError::new(
                    ErrorKind::FunctionNotImplemented,
                    "Not implemented",
                ));
            }

            let xattrs = self.get_xattrs(f_path).await.ok().ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))?;

            // Join all keys with null bytes
            let mut data = xattrs
                .iter()
                .map(|(k, _)| k.as_bytes())
                .collect::<Vec<_>>()
                .join(&b'\0');
            data.push(0); // Final null terminator

            if size == 0 {
                // Size probe: return vec of correct size
                return Ok(vec![0; data.len()]);
            }

            // Truncate if needed
            let mut truncated = data;
            truncated.truncate(size as usize);
            Ok(truncated)
        })
    }

    fn do_getxattr(
        &self,
        path: impl Into<String>,
        name: impl Into<String>,
        size: u32,
    ) -> Result<Vec<u8>, PosixError> {
        let n_str = name.into();
        self.rt.block_on(async {
            let mut f_path = path.into();
            if !f_path.starts_with('/') {
                f_path = format!("/{}", f_path);
            }
            if f_path.chars().filter(|x| *x == '/').count() <= 1 {
                return Err(PosixError::new(
                    ErrorKind::FunctionNotImplemented,
                    "Not implemented",
                ));
            }

            let xattrs = self.get_xattrs(f_path).await.ok().ok_or(PosixError::new(
                ErrorKind::NetworkUnreachable,
                "Failed to reach network.",
            ))?;

            let value = xattrs
                .iter()
                .find(|(key, _)| key == &n_str)
                .map(|(_, val)| val.clone())
                .ok_or(PosixError::new(
                    ErrorKind::Unknown(61), // Or ErrorKind::NoData if you have it
                    "Failed to find the XATTR",
                ))?;

            // Handle size == 0 (size probe)
            if size == 0 {
                return Ok(vec![0; value.len()]);
            }
            let mut truncated = value;
            truncated.truncate(size as usize);
            Ok(truncated)
        })
    }
}

impl FuseHandler<PathBuf> for NeptisFS {
    fn get_inner(&self) -> &dyn FuseHandler<PathBuf> {
        &self.inner_fs
    }

    // fn readdir(
    //     &self,
    //     _req: &RequestInfo,
    //     file_id: PathBuf,
    //     _file_handle: BorrowedFileHandle,
    // ) -> FuseResult<Vec<(OsString, <PathBuf as FileIdType>::MinimalMetadata)>> {
    //     let mut entries = vec![
    //         (OsString::from("."), FileKind::Directory),
    //         (OsString::from(".."), FileKind::Directory),
    //     ];
    //     // Only show items which have a level of the current + 1
    //     // Examples:
    //     // '' --> level 0
    //     // '/blah' --> level 2
    //     let r_path = file_id.to_str().unwrap_or_default().to_string();
    //     let mut f_path = r_path.clone();
    //     if !f_path.starts_with("/") {
    //         f_path = format!("/{}", f_path);
    //     }
    //     let show_level = if f_path.is_empty() || f_path == "/" {
    //         0
    //     } else {
    //         Self::get_level(f_path.as_str()) + 1
    //     };
    //     let get_files = self.get_files(f_path.as_str()); // Start the future outside
    //     self.rt.block_on(async {
    //         for file in get_files
    //             .await
    //             .ok()
    //             .ok_or(PosixError::new(
    //                 ErrorKind::NetworkUnreachable,
    //                 "Failed to reach network.",
    //             ))?
    //             .iter()
    //             .filter(|x| Self::get_level(x.path.as_str()) == show_level)
    //         {
    //             // We need to pull the information.
    //             // 'test/repo'
    //             let r = file.path.replace(f_path.as_str(), "");
    //             let rp = r.strip_prefix("/").unwrap_or(r.as_str()).to_string();
    //             entries.push((
    //                 OsString::from(rp),
    //                 if file.is_dir {
    //                     FileKind::Directory
    //                 } else {
    //                     FileKind::RegularFile
    //                 },
    //             ));
    //         }
    //         Ok(entries)
    //     })
    // }

    fn readdir(
        &self,
        _req: &RequestInfo,
        file_id: std::path::PathBuf,
        _file_handle: BorrowedFileHandle,
    ) -> FuseResult<Vec<(OsString, FileKind)>> {
        let mut entries = vec![
            (OsString::from("."), FileKind::Directory),
            (OsString::from(".."), FileKind::Directory),
        ];

        // Convert the incoming file_id into a string.
        let r_path = file_id.to_str().unwrap_or_default();
        let mut f_path = r_path.to_string();

        // Ensure the path starts with a "/".
        if !f_path.starts_with("/") {
            f_path = format!("/{}", f_path);
        }
        println!("Attempting to read dir {}", f_path);

        // Determine the "level" of children to show.
        // For "/" we assume level 0; otherwise add 1 to the current level.
        // let show_level = if f_path == "/" {
        //     0
        // } else {
        //     Self::get_level(&f_path) + 1
        // };
        let show_level = Self::get_level(&f_path) + 1;
        println!("Looking up level {}", show_level);

        // Retrieve files from your backend for the current path.
        // (Assume `get_files` returns a Future yielding an Option<Result<…>>.)
        let get_files = self.get_files(f_path.as_str());

        self.rt.block_on(async {
            let files = get_files
                .await
                .ok()
                .ok_or(PosixError::new(
                    ErrorKind::NetworkUnreachable,
                    "Failed to reach network.",
                ))?;

            // For each file that exactly matches the expected level,
            // extract the final component as its name.
            for file in files.iter() {
                println!("Found {} on level {}", file.path, show_level);
            }
            for file in files.iter().filter(|x| Self::get_level(&x.path) == show_level) {
                if let Some(basename) = Path::new(&file.path).file_name() {
                    entries.push((
                        OsString::from(basename),
                        if file.is_dir {
                            FileKind::Directory
                        } else {
                            FileKind::RegularFile
                        },
                    ));
                } else {
                    eprintln!("Warning: could not determine filename from path {}", file.path);
                }
            }
            Ok(entries)
        })
    }

    fn read(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        file_handle: BorrowedFileHandle,
        seek: SeekFrom,
        size: u32,
        flags: FUSEOpenFlags,
        lock_owner: Option<u64>,
    ) -> FuseResult<Vec<u8>> {
        // Attempt to pull a specific file path.
        let mut f_path = file_id.to_str().unwrap_or_default().to_string();
        if !f_path.starts_with("/") {
            f_path = format!("/{}", f_path);
        }
        self.rt.block_on(async {
            Ok(self
                .dump_file(GetForDumpApi {
                    path: f_path,
                    offset: seek.into(),
                    size: size as usize,
                })
                .await
                .ok()
                .ok_or(PosixError::new(
                    ErrorKind::NetworkUnreachable,
                    "Failed to reach network.",
                ))?)
        })
    }

    fn lookup(
        &self,
        _req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
    ) -> FuseResult<FileAttribute> {
        self.do_lookup(parent_id.join(name).to_str().unwrap_or_default())
    }

    fn getattr(
        &self,
        _req: &RequestInfo,
        file_id: PathBuf,
        _file_handle: Option<BorrowedFileHandle>,
    ) -> FuseResult<FileAttribute> {
        // Attempt to pull the information and find the file.
        if file_id.is_filesystem_root() {
            return Ok(Self::get_root_attribute());
        }
        self.do_lookup(file_id.to_str().unwrap_or_default())
    }

    fn rename(
        &self,
        _req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
        newparent: PathBuf,
        newname: &std::ffi::OsStr,
        _flags: RenameFlags,
    ) -> FuseResult<()> {
        self.do_rename(
            parent_id.join(name).to_str().unwrap_or_default(),
            newparent.join(newname).to_str().unwrap_or_default(),
        )
    }

    fn create(
        &self,
        _req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _flags: OpenFlags,
    ) -> FuseResult<(OwnedFileHandle, FileAttribute, FUSEOpenResponseFlags)> {
        self.do_create_node(parent_id.join(name).to_str().unwrap_or_default(), false)
            .map(|attr| {
                (
                    unsafe { OwnedFileHandle::from_raw(0) },
                    attr,
                    FUSEOpenResponseFlags::empty(),
                )
            })
    }

    fn mknod(
        &self,
        req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        rdev: DeviceType,
    ) -> FuseResult<FileAttribute> {
        match rdev {
            DeviceType::Directory => {
                self.do_create_node(parent_id.join(name).to_str().unwrap_or_default(), true)
            }
            DeviceType::RegularFile => {
                self.do_create_node(parent_id.join(name).to_str().unwrap_or_default(), false)
            }
            _ => Err(PosixError::new(
                ErrorKind::FunctionNotImplemented,
                "Not implemented",
            )),
        }
    }

    fn mkdir(
        &self,
        _req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
    ) -> FuseResult<FileAttribute> {
        self.do_create_node(parent_id.join(name).to_str().unwrap_or_default(), true)
    }

    fn rmdir(
        &self,
        req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
    ) -> FuseResult<()> {
        self.do_delete_node(parent_id.join(name).to_str().unwrap_or_default())
    }

    fn unlink(
        &self,
        req: &RequestInfo,
        parent_id: PathBuf,
        name: &std::ffi::OsStr,
    ) -> FuseResult<()> {
        self.do_delete_node(parent_id.join(name).to_str().unwrap_or_default())
    }

    fn fsync(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        file_handle: BorrowedFileHandle,
        datasync: bool,
    ) -> FuseResult<()> {
        Ok(())
    }

    fn flush(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        file_handle: BorrowedFileHandle,
        lock_owner: u64,
    ) -> FuseResult<()> {
        Ok(())
    }

    fn access(&self, _req: &RequestInfo, file_id: PathBuf, mask: AccessMask) -> FuseResult<()> {
        let f_str = file_id.to_str().unwrap_or_default().to_string();
        if (f_str == "data" || f_str.starts_with("repo") || f_str.is_empty())
            && mask.contains(AccessMask::CAN_WRITE)
        {
            Err(ErrorKind::PermissionDenied.to_error("You are not allowed to write here"))
        } else {
            Ok(())
        }
    }

    fn write(
        &self,
        _req: &RequestInfo,
        file_id: PathBuf,
        _file_handle: BorrowedFileHandle,
        seek: SeekFrom,
        data: Vec<u8>,
        _write_flags: FUSEWriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<u64>,
    ) -> FuseResult<u32> {
        self.do_write(file_id.to_str().unwrap_or_default(), data, seek)
    }

    fn statfs(&self, _req: &RequestInfo, file_id: PathBuf) -> FuseResult<StatFs> {
        self.do_statfs(file_id.to_str().unwrap_or_default())
    }

    fn setxattr(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        name: &std::ffi::OsStr,
        value: Vec<u8>,
        flags: FUSESetXAttrFlags,
        position: u32,
    ) -> FuseResult<()> {
        self.do_setxattr(file_id.to_str().unwrap_or_default(), name.to_str().unwrap_or_default(), value)
    }

    fn getxattr(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        name: &std::ffi::OsStr,
        size: u32,
    ) -> FuseResult<Vec<u8>> {
        self.do_getxattr(file_id.to_str().unwrap_or_default(), name.to_str().unwrap_or_default(), size)
    }

    fn listxattr(&self, req: &RequestInfo, file_id: PathBuf, size: u32) -> FuseResult<Vec<u8>> {
        self.do_listxattr(file_id.to_str().unwrap_or_default(), size)
    }

    fn removexattr(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        name: &std::ffi::OsStr,
    ) -> FuseResult<()> {
        self.do_delxattr(file_id.to_str().unwrap_or_default(), name.to_str().unwrap_or_default())
    }

    fn setattr(
        &self,
        req: &RequestInfo,
        file_id: PathBuf,
        attrs: arguments::SetAttrRequest,
    ) -> FuseResult<FileAttribute> {
        fn fix_tn(x: easy_fuser::types::TimeOrNow) -> crate::TimeOrNow {
            match x {
                easy_fuser::types::TimeOrNow::Now => crate::TimeOrNow::Now,
                easy_fuser::types::TimeOrNow::SpecificTime(x) => crate::TimeOrNow::SpecificTime(x),
            }
        }
        self.do_setattr(
            file_id.to_str().unwrap_or_default(),
            SetAttrRequest {
                size: attrs.size,
                atime: attrs.atime.map(|x| fix_tn(x)),
                mtime: attrs.mtime.map(|x| fix_tn(x)),
            },
        )
    }
}

fn main() {
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "full");
    }
    let _ = env_logger::builder()
        .is_test(false)
        .filter_level(log::LevelFilter::Trace)
        .try_init();

    let mnt = NeptisFS::new("http://127.0.0.1:8000/api", "admin", "XXXXXXXXXXX")
        .expect("Failed to run the FS!");
    easy_fuser::mount(
        mnt,
        Path::new("/home/eric/neptis-mnt"),
        &[
            MountOption::AllowOther,
            MountOption::RW,
            MountOption::DefaultPermissions,
            MountOption::FSName("Neptis FS".into()),
        ],
    )
    .expect("Failed to start mounting!");
}
