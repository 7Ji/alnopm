use std::{collections::HashMap, fs::{read_dir, File}, io::{Read, Seek}, path::Path};

#[derive(Default)]
pub struct Package {
    pub name: String,
    pub version: String,
}

#[derive(Default)]
pub struct Db {
    // pub name: String,
    pub packages: Vec<Package>,
}

pub enum Error {
    IoError(std::io::Error),
    BrokenDB,
    DuplicatedDB,
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn buffer_try_from_reader<R: Read>(mut reader: R) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    match reader.read_to_end(&mut buffer) {
        Ok(_) => Ok(buffer),
        Err(e) => {
            log::error!("Failed to read file into buffer: {}", e);
            Err(e.into())
        },
    }
}

fn file_try_from_path<P: AsRef<Path>>(path: P) -> Result<File> {
    File::open(&path).map_err(|e|{
        log::error!("Failed to open file from path '{}': {}",
            path.as_ref().display(), e);
        e.into()
    })
}

fn buffer_try_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    buffer_try_from_reader(&mut file_try_from_path(path)?)
}

impl Package {
    fn try_from_buffer(buffer: &[u8]) -> Result<Self> {
        let package = Self::default();
        // for line in buffer.split
        Ok(package)
    }

    fn try_from_reader<R: Read>(reader: R) -> Result<Self> {
        Self::try_from_buffer(&buffer_try_from_reader(reader)?)

    }

    fn try_from_tar_entry(entry: tar::Entry<&[u8]>) -> Result<Self> {
        Self::try_from_reader(entry)
    }
}

const MAGIC_GZIP: [u8; 2] = [0x1f, 0x8b];
const MAGIC_BZIP2: [u8; 3] = [0x42, 0x5a, 0x68]; // BZh
const MAGIC_XZ: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]; // 0xfd + 7zXZ + \0
const MAGIC_ZSTD: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd]; 
const MAGIC_LRZIP: [u8; 4] = [0x4c, 0x52, 0x5a, 0x49]; // LRZI
const MAGIC_LZOP: [u8; 4] = [0x89, 0x4c, 0x5a, 0x4f]; // 0x89 + LZO
const MAGIC_LZW: [u8; 2] = [0x1f, 0x9d];
const MAGIC_LZ4: [u8; 4] = [0x04, 0x22, 0x4d, 0x18]; 
const MAGIC_LZIP: [u8; 4] = [0x4c, 0x5a, 0x49, 0x50]; // LZIP
const MAGIC_TAR_PREFIX: [u8; 5] = [0x75, 0x73, 0x74, 0x61, 0x72]; // "ustar"
const MAGIC_TAR_SUFFIX_BSD: [u8; 3] = [0x00, 0x30, 0x30]; // "\0""00"
const MAGIC_TAR_SUFFIX_GNU: [u8; 3] = [0x20, 0x20, 0x00]; // "  \0"
const MAGIC_TAR_BSD: [u8; 8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30]; // "ustar\0  "
const MAGIC_TAR_GNU: [u8; 8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]; // "ustar\0  "

fn buffer_try_decompress(buffer: &[u8]) -> Result<Vec<u8>> {
    /// Magic:
    Ok(Default::default())
}

fn is_buffer_tar(buffer: &[u8]) -> bool {
    if buffer.len() < 512 || buffer[257..262] != MAGIC_TAR_PREFIX ||
            buffer[262..265] != MAGIC_TAR_SUFFIX_BSD || 
            buffer[262..265] != MAGIC_TAR_SUFFIX_GNU
    {
        log::warn!("Buffer of size {} could not be tar", buffer.len());
        return false
    }
    match tar::Archive::new(buffer).entries() {
        Ok(entries) => {
            for entry in entries {
                if let Err(e) = entry {
                    log::warn!("Failed to parse tar entry : {}. \
                        Buffer is probably not tar", e);
                    return false
                }
            }
            true
        },
        Err(e) => {
            log::warn!("Failed to parse tar entries: {}. \
                Buffer is probably not tar", e);
            false
        },
    }
}

impl Db {
    fn try_from_buffer_tar(buffer: &[u8]) -> Result<Self> {
        let mut archive = tar::Archive::new(buffer);
        let entries = match archive.entries() {
            Ok(entries) => entries,
            Err(e) => {
                log::error!("Failed to parse tar entries: {}", e);
                return Err(Error::BrokenDB)
            },
        };
        let mut db = Self::default();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    log::error!("Failed to parse tar entry : {}. \
                        Buffer is probably not tar", e);
                    return Err(Error::BrokenDB)
                },
            };
            let path_bytes = entry.path_bytes();
            if path_bytes.is_empty() || 
                path_bytes[path_bytes.len()] == b'/' || 
                ! path_bytes.ends_with(b"/desc")
            {
                continue
            }
            db.packages.push(Package::try_from_tar_entry(entry)?)
        }
        Ok(db)
    }

    fn try_from_buffer_gzip(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_bzip2(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_xz(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_zstd(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_lrzip(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_lzop(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_lzw(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_lz4(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_lzip(buffer: &[u8]) -> Result<Self> {
        Self::try_from_buffer_tar(buffer)
    }

    fn try_from_buffer_any(buffer: &[u8]) -> Result<Self> {
        if is_buffer_tar(buffer) {
            if let Ok(db) = Self::try_from_buffer_tar(buffer) {
                return Ok(db)
            }
            log::warn!("Failed to parse buffer of DB as plain tar although \
                it looked like tar, trying to parse it as compressed data");
        }
        // Magic of all compressed formats are mutually exclusive
        if buffer.len() >= 6 {
            if buffer[0..6] == MAGIC_XZ {
                return Self::try_from_buffer_xz(buffer)
            }
        }
        if buffer.len() >= 4 {
            if buffer[0..4] == MAGIC_ZSTD {
                return Self::try_from_buffer_zstd(buffer)
            } 
            if buffer[0..4] == MAGIC_LRZIP {
                return Self::try_from_buffer_lrzip(buffer)
            }
            if buffer[0..4] == MAGIC_LZOP {
                return Self::try_from_buffer_lzop(buffer)
            }
            if buffer[0..4] == MAGIC_LZ4 {
                return Self::try_from_buffer_lz4(buffer)
            }
            if buffer[0..4] == MAGIC_LZIP {
                return Self::try_from_buffer_lzip(buffer)
            }
        }
        if buffer.len() >= 3 {
            if buffer[0..3] == MAGIC_BZIP2 {
                return Self::try_from_buffer_bzip2(buffer)
            }
        }
        if buffer.len() >= 2 {
            if buffer[0..2] == MAGIC_GZIP {
                return Self::try_from_buffer_gzip(buffer)
            }
            if buffer[0..2] == MAGIC_LZW {
                return Self::try_from_buffer_lzw(buffer)
            }
        }
        log::error!("Failed to parse buffer of DB as either plain tar or \
                    compressed tar");
        Err(Error::BrokenDB)
    }

    fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::try_from_buffer_any(&buffer_try_from_path(path)?)
    }
}

#[derive(Default)]
pub struct Dbs {
    dbs: HashMap<String, Db>
}

impl Dbs {
    /// Try to read DBs from a folder, commonly `/var/lib/pacman/sync`
    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let dir = match read_dir(path) {
            Ok(dir) => dir,
            Err(e) => {
                log::error!("Failed to open DBs dir '{}' to scan: {}",
                    path.display(), e);
                return Err(e.into())
            },
        };
        let mut dbs = Self::default();
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    log::error!("Failed to read entry from DB dir '{}': {}",
                        path.display(), e);
                    return Err(e.into())
                },
            };
            match entry.file_type() {
                Ok(file_type) => if file_type.is_dir() {
                    continue
                },
                Err(e) => {
                    log::error!("Failed to read file type of entry from DB dir \
                        '{}': {}", path.display(), e);
                    return Err(e.into())
                },
            }
            let file_name = entry.file_name();
            let bytes = file_name.as_encoded_bytes();
            if ! bytes.ends_with(b".db") {
                continue
            }
            let name_raw = &bytes[..(bytes.len() - 3)];
            let name= String::from_utf8_lossy(name_raw).into_owned();
            log::info!("Adding DB {}", name);
            let db = Db::try_from_path(entry.path())?;
            if dbs.dbs.insert(name, db).is_some() {
                log::error!("Duplicated DB '{}'", 
                    String::from_utf8_lossy(name_raw));
                return Err(Error::DuplicatedDB)
            }
        }
        Ok(dbs)
    }
}