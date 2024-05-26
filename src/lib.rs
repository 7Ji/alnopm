use std::{fs::File, io::Read, path::Path};

struct Package {
    name: String,
    version: String,
    
}

#[derive(Default)]
struct Db {
    name: String,
    packages: Vec<Package>,
}

enum Error {
    IoError(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

type Result<T> = std::result::Result<T, Error>;

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

const MAGIC_GZIP: [u8; 2] = [0x1f, 0x8b];
const MAGIC_BZIP2: [u8; 3] = [0x42, 0x5a, 0x68]; // BZh
const MAGIC_XZ: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]; // 0xfd + 7zXZ + \0
const MAGIC_ZSTD: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd]; 
const MAGIC_LRZIP: [u8; 4] = [0x4c, 0x52, 0x5a, 0x49]; // LRZI
const MAGIC_LZOP: [u8; 4] = [0x89, 0x4c, 0x5a, 0x4f]; // 0x89 + LZO
const MAGIC_LZW: [u8; 2] = [0x1f, 0x9d];
const MAGIC_LZ4: [u8; 4] = [0x04, 0x22, 0x4d, 0x18]; 
const MAGIC_LZIP: [u8; 4] = [0x4c, 0x5a, 0x49, 0x50]; // LZIP
const MAGIC_TAR: [u8; 8] = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x0]; // "ustar   \0"


// enum Magic {
//     Gzip = [0x1f, 0x8b],
// }

fn buffer_try_decompress(buffer: &[u8]) -> Result<Vec<u8>> {
    /// Magic:
    Ok(Default::default())
}

impl Db {
    fn try_from_buffer<S: Into<String>>(name: S, buffer: &[u8]) -> Result<Self> {
        Ok(Default::default())
    }

    fn try_from_reader<S: Into<String>, R: Read>(name: S, reader: R) -> Result<Self> {
        Self::try_from_buffer(name, &buffer_try_from_reader(reader)?)
    }

    fn try_from_path<S: Into<String>, P: AsRef<Path>>(name: S, path: P) -> Result<Self> {
        Self::try_from_reader(name, file_try_from_path(path)?)
    }
}