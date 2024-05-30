use std::{collections::HashMap, fs::{read_dir, File}, io::{BufRead, BufReader, Read, Seek}, path::Path};

use base64::Engine;
use hex::FromHex;
use pkgbuild::{Architecture, CheckDependency, Conflict, Dependency, MakeDependency, Md5sum, OptionalDependency, PlainVersion, Provide, Replace, Sha256sum};

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Copy, Debug, Default)]
enum PackageParsingState {
    #[default]
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

#[derive(Clone, Debug, Default)]
pub struct Db {
    // pub name: String,
    pub packages: Vec<Package>,
}

#[derive(Clone, Debug)]
pub enum Error {
    /// Collapsed IO Error
    IoError(String), 
    BrokenDB,
    DuplicatedDB,
    ParseIntError(std::num::ParseIntError),
    FromHexError(hex::FromHexError),
    Base64DecodeError(base64::DecodeError),
    PkgbuildRsError(pkgbuild::Error),
    #[cfg(feature = "db_xz")]
    /// Collapsed LZMA Error
    LzmaError(String),
    DecompressorNotImplemented(&'static str),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO Error: {}", e),
            Error::BrokenDB => write!(f, "Broken DB"),
            Error::DuplicatedDB => write!(f, "Duplicated DB"),
            Error::ParseIntError(e) 
                => write!(f, "Parse Int Error: {}", e),
            Error::FromHexError(e) 
                => write!(f, "From Hex Error: {}", e),
            Error::Base64DecodeError(e) 
                => write!(f, "Base64 Decode Error: {}", e),
            Error::PkgbuildRsError(e) 
                => write!(f, "PKGBUILD-rs Error: {}", e),
            Error::LzmaError(e) 
                => write!(f, "LZMA Error: {}", e),
            Error::DecompressorNotImplemented(decompressor) 
                => write!(f, "Decompressor '{}' Not Implemented", decompressor),
        }
    }
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

impl_from_error!(std::num::ParseIntError, ParseIntError);
impl_from_error!(hex::FromHexError, FromHexError);
impl_from_error!(base64::DecodeError, Base64DecodeError);
impl_from_error!(pkgbuild::Error, PkgbuildRsError);

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(format!("{}", value))
    }
}

#[cfg(feature = "db_xz")]
impl From<lzma_rs::error::Error> for Error {
    fn from(value: lzma_rs::error::Error) -> Self {
        Self::LzmaError(format!("{}", value))
    }
}

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

#[cfg(feature = "db_gz")]
const MAGIC_GZIP: [u8; 2] = [0x1f, 0x8b];
#[cfg(feature = "db_bz2")]
const MAGIC_BZIP2: [u8; 3] = [0x42, 0x5a, 0x68]; // BZh
#[cfg(feature = "db_xz")]
const MAGIC_XZ: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]; // 0xfd + 7zXZ + \0
#[cfg(feature = "db_zst")]
const MAGIC_ZSTD: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd]; 
#[cfg(feature = "db_lrz")]
const MAGIC_LRZIP: [u8; 4] = [0x4c, 0x52, 0x5a, 0x49]; // LRZI
#[cfg(feature = "db_lzo")]
const MAGIC_LZOP: [u8; 4] = [0x89, 0x4c, 0x5a, 0x4f]; // 0x89 + LZO
#[cfg(feature = "db_Z")]
const MAGIC_LZW: [u8; 2] = [0x1f, 0x9d];
#[cfg(feature = "db_lz4")]
const MAGIC_LZ4: [u8; 4] = [0x04, 0x22, 0x4d, 0x18]; 
#[cfg(feature = "db_lz")]
const MAGIC_LZIP: [u8; 4] = [0x4c, 0x5a, 0x49, 0x50]; // LZIP
const MAGIC_TAR_PREFIX: [u8; 5] = [0x75, 0x73, 0x74, 0x61, 0x72]; // "ustar"
const MAGIC_TAR_SUFFIX_BSD: [u8; 3] = [0x00, 0x30, 0x30]; // "\0""00"
const MAGIC_TAR_SUFFIX_GNU: [u8; 3] = [0x20, 0x20, 0x00]; // "  \0"
const _MAGIC_TAR_BSD: [u8; 8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30]; // "ustar\0""00"
const _MAGIC_TAR_GNU: [u8; 8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]; // "ustar  \0"

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

fn seek_get_position_checked<S: Seek>(mut stream: S) -> Result<u64> {
    stream.stream_position().map_err(|e| {
        log::error!("Failed to get current possition: {}", e);
        e.into()
    })
}

/// Figure out whether the reader corresponds to a tar from current offset.
/// 
/// The offset would be reset to the value same as before the routine.
fn is_reader_tar<R: Read + Seek>(mut reader: R) -> Result<bool> {
    let position = seek_get_position_checked(&mut reader)?;
    let mut buffer = [0; 512];
    let r = match reader.read(&mut buffer) {
        Ok(size) => {
            if size >= 512 &&  buffer[257..262] == MAGIC_TAR_PREFIX &&
                (buffer[262..265] == MAGIC_TAR_SUFFIX_BSD ||
                 buffer[262..265] == MAGIC_TAR_SUFFIX_GNU) 
            {
                match tar::Archive::new(&mut reader).entries() {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        log::warn!("Failed to parse tar entries: {}. \
                            Buffer is probably not tar", e);
                        Ok(false)
                    }
                }
            } else { // Shorter than a single tar header
                Ok(false)
            }
        },
        Err(e) => {
            log::error!("Failed to read buffer to figure out reader is tar or \
                not: {}", e);
            Err(e.into())
        },
    };
    match reader.seek(std::io::SeekFrom::Start(position)) {
        Ok(new_position) => {
            if new_position != position {
                log::error!("Reader for tar was not reset to the initial seek \
                    offset: current {} != original {}", new_position, position);
                Err(Error::IoError("Incomplete seek".into()))
            } else {
                r
            }
        },
        Err(e) => {
            log::error!("Failed to seek back: {}", e);
            Err(e.into())
        },
    }
}

impl Db {
    fn try_from_bufreader_tar(buffer: &[u8]) -> Result<Self> {
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

    #[cfg(feature = "db_gz")]
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

    #[cfg(feature = "db_bz2")]
    fn try_from_buffer_bzip2(buffer: &[u8]) -> Result<Self> {
        let mut new_buffer = Vec::new();
        let mut decoder = bzip2::read::BzDecoder::new(buffer);
        match decoder.read_to_end(&mut new_buffer) {
            Ok(size) => {
                log::debug!("Decompressed {} bytes from .bz2", size);
                Self::try_from_buffer_tar(&new_buffer)
            },
            Err(e) => {
                log::error!("Failed to decompress bzip2: {}", e);
                Err(e.into())
            },
        }
    }

    #[cfg(feature = "db_xz")]
    fn try_from_buffer_xz(buffer: &[u8]) -> Result<Self> {
        let mut new_buffer = Vec::new();
        let mut wrapped_buffer = BufReader::new(buffer);
        match lzma_rs::xz_decompress(
            &mut wrapped_buffer, &mut new_buffer
        ) {
            Ok(_) => Self::try_from_buffer_tar(&new_buffer),
            Err(e) => {
                log::error!("Failed to decompress xz: {}", e);
                Err(e.into())
            },
        }
    }

    #[cfg(feature = "db_zst")]
    fn try_from_buffer_zstd(buffer: &[u8]) -> Result<Self> {
        match zstd::decode_all(buffer) {
            Ok(buffer) => Self::try_from_buffer_tar(&buffer),
            Err(e) => {
                log::error!("Failed to decompress zstd: {}", e);
                Err(e.into())
            },
        }
    }

    /// Todo: Port from libarchive:
    /// https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_filter_lrzip.c
    #[cfg(feature = "db_lrz")]
    fn try_from_buffer_lrzip(_buffer: &[u8]) -> Result<Self> {
        Err(Error::DecompressorNotImplemented(".lrz (lrzip)"))
    }

    /// Todo: Port from libarchive:
    /// https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_filter_lzop.c
    #[cfg(feature = "db_lzo")]
    fn try_from_buffer_lzop(_buffer: &[u8]) -> Result<Self> {
        Err(Error::DecompressorNotImplemented(".lzo (lzop)"))
    }

    /// Todo: Port from libarchive:
    /// https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_filter_compress.c
    #[cfg(feature = "db_Z")]
    fn try_from_buffer_lzw(_buffer: &[u8]) -> Result<Self> {
        Err(Error::DecompressorNotImplemented(".Z (LZW)"))
    }

    #[cfg(feature = "db_lz4")]
    fn try_from_buffer_lz4(buffer: &[u8]) -> Result<Self> {
        // LZ4 minimum size is 20 (header)
        let mut decoder = 
            lz4_flex::frame::FrameDecoder::new(buffer);
        let mut new_buffer = Vec::new();
        match decoder.read_to_end(&mut new_buffer) {
            Ok(size) => {
                log::debug!("Decompressed {} bytes from .lz4", size);
                Self::try_from_buffer_tar(&new_buffer)
            },
            Err(e) => {
                log::error!("Failed to decompress lz4: {}", e);
                Err(e.into())
            },
        }
    }

    /// Todo: Add lzip support to lzma-rs
    #[cfg(feature = "db_lz")]
    fn try_from_buffer_lzip(_buffer: &[u8]) -> Result<Self> {
        Err(Error::DecompressorNotImplemented(".lz (lzip)"))
    }

    fn try_from_bufreader_any<B: BufRead + Seek>(reader: B) -> Result<Self> {
        if is_reader_tar(&mut reader)? {

        }
        if is_buffer_tar(buffer) {
            if let Ok(db) = Self::try_from_buffer_tar(buffer) {
                return Ok(db)
            }
            log::warn!("Failed to parse buffer of DB as plain tar although \
                it looked like tar, trying to parse it as compressed data");
        }
        // Magic of all compressed formats are mutually exclusive
        if buffer.len() >= 6 {
            #[cfg(feature = "db_xz")]
            if buffer[0..6] == MAGIC_XZ {
                return Self::try_from_buffer_xz(buffer)
            }
        }
        if buffer.len() >= 4 {
            #[cfg(feature = "db_zst")]
            if buffer[0..4] == MAGIC_ZSTD {
                return Self::try_from_buffer_zstd(buffer)
            } 
            #[cfg(feature = "db_lrz")]
            if buffer[0..4] == MAGIC_LRZIP {
                return Self::try_from_buffer_lrzip(buffer)
            }
            #[cfg(feature = "db_lzo")]
            if buffer[0..4] == MAGIC_LZOP {
                return Self::try_from_buffer_lzop(buffer)
            }
            #[cfg(feature = "db_lz4")]
            if buffer[0..4] == MAGIC_LZ4 {
                return Self::try_from_buffer_lz4(buffer)
            }
            #[cfg(feature = "db_lz")]
            if buffer[0..4] == MAGIC_LZIP {
                return Self::try_from_buffer_lzip(buffer)
            }
        }
        if buffer.len() >= 3 {
            #[cfg(feature = "db_bz2")]
            if buffer[0..3] == MAGIC_BZIP2 {
                return Self::try_from_buffer_bzip2(buffer)
            }
        }
        if buffer.len() >= 2 {
            #[cfg(feature = "db_gz")]
            if buffer[0..2] == MAGIC_GZIP {
                return Self::try_from_buffer_gzip(buffer)
            }
            #[cfg(feature = "db_Z")]
            if buffer[0..2] == MAGIC_LZW {
                return Self::try_from_buffer_lzw(buffer)
            }
        }
        log::error!("Failed to parse buffer of DB as either plain tar or \
                    compressed tar");
        Err(Error::BrokenDB)
    }

    fn try_from_reader_any<R: Read + Seek>(reader: R) -> Result<Self> {
        Self::try_from_bufreader_any(BufReader::new(reader))
    }

    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::try_from_reader_any(file_try_from_path(path)?)
    }
}

#[derive(Clone, Debug, Default)]
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