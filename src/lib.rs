use std::{collections::HashMap, fs::{read_dir, File}, io::{Read, Seek}, os::unix::raw::time_t, path::{Path, PathBuf}};

use base64::Engine;
use hex::FromHex;
use pkgbuild::{Architecture, CheckDependency, Conflict, Dependency, MakeDependency, Md5sum, OptionalDependency, PlainVersion, Provide, Replace, Sha256sum};

#[derive(Default, Debug)]
pub struct Package {
    pub filename: String,
    pub name: String,
    pub base: String,
    pub version: PlainVersion,
    pub desc: String,
    pub groups: Vec<String>,
    pub csize: usize, // Download / Compressed size
    pub isize: usize, // Installation size
    pub md5sum: Md5sum, // Shouldn't really be used after https://gitlab.archlinux.org/pacman/pacman/-/commit/310bf878fcdebbb34c4d68afa37e338c2ad34499
    pub sha256sum: Sha256sum,
    pub pgpsig: Vec<u8>,
    pub url: String,
    pub license: Vec<String>,
    pub arch: Vec<Architecture>,
    pub builddate: i64,
    pub packager: String,
    pub replaces: Vec<Replace>,
    pub conflicts: Vec<Conflict>,
    pub provides: Vec<Provide>,
    pub depends: Vec<Dependency>,
    pub optdepends: Vec<OptionalDependency>,
    pub makedepends: Vec<MakeDependency>,
    pub checkdepends: Vec<CheckDependency>,
}

#[derive(Clone, Copy, Debug)]
enum PackageParsingState {
    None,
    FileName,
    Name,
    Base,
    Version,
    Desc,
    Groups,
    CSize,
    ISize,
    Md5Sum,
    Sha256Sum,
    PgpSig,
    Url,
    License,
    Arch,
    BuildDate,
    Packager,
    Replaces,
    Conflicts,
    Provides,
    Depends,
    OptDepends,
    MakeDepends,
    CheckDepends,
}

#[derive(Default, Debug)]
pub struct Db {
    // pub name: String,
    pub packages: Vec<Package>,
}

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    BrokenDB,
    DuplicatedDB,
    ParseIntError(std::num::ParseIntError),
    FromHexError(hex::FromHexError),
    Base64DecodeError(base64::DecodeError),
    PkgbuildRsError(pkgbuild::Error),
}

macro_rules! impl_from_error {
    ($from_type: ty, $into_type: tt) => {
        impl From<$from_type> for Error {
            fn from(value: $from_type) -> Self {
                Self::$into_type(value)
            }
        }
    };
}

impl_from_error!(std::io::Error, IoError);
impl_from_error!(std::num::ParseIntError, ParseIntError);
impl_from_error!(hex::FromHexError, FromHexError);
impl_from_error!(base64::DecodeError, Base64DecodeError);
impl_from_error!(pkgbuild::Error, PkgbuildRsError);


pub type Result<T> = std::result::Result<T, Error>;

fn buffer_try_from_reader<R: Read>(mut reader: R) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    match reader.read_to_end(&mut buffer) {
        Ok(size) => {
            log::debug!("Read {} bytes from reader", size);
            Ok(buffer)
        },
        Err(e) => {
            log::error!("Failed to read file into buffer: {}", e);
            Err(e.into())
        },
    }
}

fn file_try_from_path<P: AsRef<Path>>(path: P) -> Result<File> {
    log::debug!("Opened file '{}'", path.as_ref().display());
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
        let mut package = Self::default();
        let mut state = PackageParsingState::None;
        let mut state_record = 
            [false; PackageParsingState::CheckDepends as usize + 1];
        for line in buffer.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                state = PackageParsingState::None;
                continue
            }
            macro_rules! fill_string{
                ($value: ident) => {{
                    let $value = String::from_utf8_lossy(line);
                    if ! package.$value.is_empty() {
                        log::error!("Duplicated {}: {}", 
                            stringify!($value), $value);
                        return Err(Error::BrokenDB)
                    }
                    package.$value = $value.into();
                }};
            }
            macro_rules! fill_num {
                ($value: ident, $type: ty) => {{
                    if package.$value != 0 {
                        log::error!("Duplicated {}: {}", 
                            stringify!($value), package.$value);
                        return Err(Error::BrokenDB);
                    }
                    let $value: $type = match 
                        String::from_utf8_lossy(line).parse() 
                    {
                        Ok(size) => size,
                        Err(e) => {
                            log::error!("Failed to parse {}: {}", 
                                stringify!($value), e);
                            return Err(e.into())
                        },
                    };
                    package.$value = $value
                }};
            }
            macro_rules! fill_hash {
                ($value: ident) => {{
                    match FromHex::from_hex(line) {
                        Ok($value) => package.$value = $value,
                        Err(e) => {
                            log::error!("Failed to parse {} from hex: {}", 
                                stringify!($value), e);
                            return Err(e.into())
                        },
                    }
                }};
            }
            match state {
                PackageParsingState::None => {
                    if line.len() < 2 {
                        log::error!("DB entry line too short");
                        return Err(Error::BrokenDB)
                    }
                    if line[0] != b'%' || line[line.len() - 1] != b'%' {
                        return Err(Error::BrokenDB)
                    }
                    let title = &line[1..line.len() - 1];
                    state = match title {
                        b"FILENAME" => PackageParsingState::FileName,
                        b"NAME" => PackageParsingState::Name,
                        b"BASE" => PackageParsingState::Base,
                        b"VERSION" => PackageParsingState::Version,
                        b"DESC" => PackageParsingState::Desc,
                        b"GROUPS" => PackageParsingState::Groups,
                        b"CSIZE" => PackageParsingState::CSize,
                        b"ISIZE" => PackageParsingState::ISize,
                        b"MD5SUM" => PackageParsingState::Md5Sum,
                        b"SHA256SUM" => PackageParsingState::Sha256Sum,
                        b"PGPSIG" => PackageParsingState::PgpSig,
                        b"URL" => PackageParsingState::Url,
                        b"LICENSE" => PackageParsingState::License,
                        b"ARCH" => PackageParsingState::Arch,
                        b"BUILDDATE" => PackageParsingState::BuildDate,
                        b"PACKAGER" => PackageParsingState::Packager,
                        b"REPLACES" => PackageParsingState::Replaces,
                        b"CONFLICTS" => PackageParsingState::Conflicts,
                        b"PROVIDES" => PackageParsingState::Provides,
                        b"DEPENDS" => PackageParsingState::Depends,
                        b"OPTDEPENDS" => PackageParsingState::OptDepends,
                        b"MAKEDEPENDS" => PackageParsingState::MakeDepends,
                        b"CHECKDEPENDS" => PackageParsingState::CheckDepends,
                        _ => {
                            log::error!("Illegal section title in DB: {}", 
                                String::from_utf8_lossy(title));
                            return Err(Error::BrokenDB)
                        }
                    };
                    let record = &mut state_record[state as usize];
                    if *record {
                        log::error!("Duplicated section in DB: {}",
                            String::from_utf8_lossy(title));
                        return Err(Error::BrokenDB)
                    }
                    *record = true
                },
                PackageParsingState::FileName => fill_string!(filename),
                PackageParsingState::Name => fill_string!(name),
                PackageParsingState::Base => fill_string!(base),
                PackageParsingState::Version => {
                    let version = &package.version;
                    if ! (version.pkgver.is_empty() && version.pkgrel.is_empty() 
                        && version.epoch.is_empty()) 
                    {
                        log::error!("Duplicated version {:?}", version);
                        return Err(Error::BrokenDB)
                    }
                    package.version = line.into()
                },
                PackageParsingState::Desc => fill_string!(desc),
                PackageParsingState::Groups =>
                    package.groups.push(String::from_utf8_lossy(line).into()),
                PackageParsingState::CSize => fill_num!(csize, usize),
                PackageParsingState::ISize => fill_num!(isize, usize),
                PackageParsingState::Md5Sum => fill_hash!(md5sum),
                PackageParsingState::Sha256Sum => fill_hash!(sha256sum),
                PackageParsingState::PgpSig => {
                    if ! package.pgpsig.is_empty() {
                        log::error!("Duplicated PGP signature: {}", 
                            String::from_utf8_lossy(&package.pgpsig));
                        return Err(Error::BrokenDB)
                    }
                    let engine = 
                        base64::engine::general_purpose::STANDARD;
                    match engine.decode(line) {
                        Ok(bytes) => package.pgpsig = bytes,
                        Err(e) => {
                            log::error!("Failed to decode base64 encoded PGP \
                                signature: {}", e);
                            return Err(e.into())
                        },
                    }
                },
                PackageParsingState::Url => fill_string!(url),
                PackageParsingState::License => 
                    package.license.push(String::from_utf8_lossy(line).into()),
                PackageParsingState::Arch => 
                    package.arch.push(Architecture::from(line)),
                PackageParsingState::BuildDate => fill_num!(builddate, i64),
                PackageParsingState::Packager => fill_string!(packager),
                PackageParsingState::Replaces => 
                    package.replaces.push(Replace::from(line)),
                PackageParsingState::Conflicts => 
                    package.conflicts.push(Conflict::from(line)),
                PackageParsingState::Provides => 
                    match Provide::try_from(line) {
                        Ok(provide) => package.provides.push(provide),
                        Err(e) => {
                            log::error!("Failed to parse provide: {}", e);
                            return Err(e.into())
                        },
                    },
                PackageParsingState::Depends => 
                    package.depends.push(Dependency::from(line)),
                PackageParsingState::OptDepends => 
                    package.optdepends.push(OptionalDependency::from(line)),
                PackageParsingState::MakeDepends => 
                    package.makedepends.push(MakeDependency::from(line)),
                PackageParsingState::CheckDepends => 
                    package.checkdepends.push(CheckDependency::from(line)),
            }
        }
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
            (buffer[262..265] != MAGIC_TAR_SUFFIX_BSD &&
             buffer[262..265] != MAGIC_TAR_SUFFIX_GNU)
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
                path_bytes[path_bytes.len() - 1] == b'/' || 
                ! path_bytes.ends_with(b"/desc")
            {
                continue
            }
            if log::log_enabled!(log::Level::Debug) {
                match entry.path() {
                    Ok(path) => log::debug!(
                        "Parsing entry {}", path.display()),
                    Err(e) => {
                        log::error!("Failed to get entry path: {}", e);
                        log::debug!("Parsing entry {}", 
                            String::from_utf8_lossy(&path_bytes));
                    },
                }
            }
            db.packages.push(Package::try_from_tar_entry(entry)?)
        }
        Ok(db)
    }

    fn try_from_buffer_gzip(buffer: &[u8]) -> Result<Self> {
        let mut new_buffer = Vec::new();
        match flate2::read::GzDecoder::new(buffer)
            .read_to_end(&mut new_buffer) 
        {
            Ok(size) => {
                log::debug!("Decompressed {} bytes from .gz", size);
                Self::try_from_buffer_tar(&new_buffer)
            },
            Err(e) => {
                log::error!("Failed to decompress gzip: {}", e);
                Err(e.into())
            },
        }
    }

    fn try_from_buffer_bzip2(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_xz(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_zstd(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_lrzip(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_lzop(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_lzw(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_lz4(buffer: &[u8]) -> Result<Self> {
        todo!()
    }

    fn try_from_buffer_lzip(buffer: &[u8]) -> Result<Self> {
        todo!()
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

    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::try_from_buffer_any(&buffer_try_from_path(path)?)
    }
}

#[derive(Default)]
pub struct Dbs {
    pub dbs: HashMap<String, Db>
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