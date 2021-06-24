//! Library to parse ld.so.cache according to the numerous format define in glibc
//!
//! This library doesn't use any c bindings or doesn't try to create a structure to match
//! it over the data, it uses plain parsing and thus allow the definition of endianness.
//! As parsing ld.so.cache is useful to get access to the symbol, the parsing is done
//! stringently as well as fastly.
//!
//! If you want to make a dirt cheap parser for ld.so.cache a simple call to
//! `strings /etc/ld.so.cache` will do.

use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;

pub const LD_SO_CACHE: &str = "/etc/ld.so.cache";
pub const OLD_HEADER: &str = "ld.so-1.7.0";
pub const OLD_VERSION: &str = "1.7.0";
// 11 +1 = 12 bytes or 3x4 bounds
pub const PADDING_OLD: usize = 1;
pub const HEADER: &str = "glibc-ld.so.cache";
pub const CURRENT_VERSION: &str = "1.1";
pub const VERSION_SIZE: usize = 3;
// 17+3+0 = 20 bytes or 5x4 bounds
pub const PADDING_NEW: usize = 0;
pub const HEADER_LEN: usize = if OLD_HEADER.len() > HEADER.len() {
    OLD_HEADER.len()
} else {
    HEADER.len()
};

// we consider char to be of u8 and not full unicode as rust defines it
pub const U8_SIZE: usize = std::mem::size_of::<u8>();
pub const U32_SIZE: usize = std::mem::size_of::<u32>();
pub const U64_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Clone, Debug, Default)]
pub struct Cache {
    /// Boolean to say what type of parser should be used
    _is_old: bool,
    /// Cache version as parsed from ld.so.cache (usually 1.1 for the new one)
    pub version: String,
    /// number of entries in the cache (parsed from the ld.so.cache)
    pub count: u32,
    /// string table length
    pub strlen: Option<u32>,
    /// flags for endianness (as of 2.33) values are
    ///     0: Not Set
    ///     1: Invalid
    ///     2: Little
    ///     3: Big
    pub flags: Option<u8>,
    /// File offset of the extension directory (as of 2.33)
    pub extension_offset: Option<u32>,
    /// list of entries, we use a hashmap as the use case
    /// is more to retrieve a path from a lib name
    pub entries: HashMap<String, Entry>,
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub flags: i32,
    pub libname: Vec<String>,
    pub path: Vec<String>,
    key: u32,
    value: u32,
    pub os_version: Option<u32>,
    pub hwcap: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },
    #[error("Invalid size for the data, should be at least {0}")]
    InvalidSize(usize),
    #[error("Missing a slice at index {0}")]
    MissingSlice(u32),
    #[error(
        "Invalid string at index {index:?} for stream starting with {stream:?} with {error:?}"
    )]
    InvalidString {
        index: usize,
        stream: Vec<u8>,
        error: std::str::Utf8Error,
    },
    #[error("Unknown")]
    Unknown,
}

#[derive(Copy, Clone, Debug)]
pub enum TargetEndian {
    Native,
    Big,
    Little,
}

/// The cache have two possible interpretations
/// ```c
/// struct file_entry
/// {
///   int flags;		/* This is 1 for an ELF library.  */
///   unsigned int key, value; /* String table indices.  */
/// };
///
/// struct cache_file
/// {
///   char magic[sizeof CACHEMAGIC - 1];
///   unsigned int nlibs;
///   struct file_entry libs[0];
/// };
///
/// #define CACHEMAGIC_NEW "glibc-ld.so.cache"
/// #define CACHE_VERSION "1.1"
/// #define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION
///
///
/// struct file_entry_new
/// {
///   int32_t flags;		/* This is 1 for an ELF library.  */
///   uint32_t key, value;		/* String table indices.  */
///   uint32_t osversion;		/* Required OS version.	 */
///   uint64_t hwcap;		/* Hwcap entry.	 */
/// };
///
/// struct cache_file_new
/// {
///   char magic[sizeof CACHEMAGIC_NEW - 1];
///   char version[sizeof CACHE_VERSION - 1];
///   uint32_t nlibs;		/* Number of entries.  */
///   uint32_t len_strings;		/* Size of string table. */
///   uint32_t unused[5];		/* Leave space for future extensions and align to 8 byte boundary.  */
///   struct file_entry_new libs[0]; /* Entries describing libraries.  */
///   /* After this the string table of size len_strings is found.	*/
/// };
/// ```
/// as of 2.33 we know use 2 of the unused
/// ```c
/// struct cache_file_new {
///   char magic[sizeof CACHEMAGIC_NEW - 1];
///   char version[sizeof CACHE_VERSION - 1];
///   uint32_t nlibs;		/* Number of entries.  */
///   uint32_t len_strings;		/* Size of string table. */
///
///   /* flags & cache_file_new_flags_endian_mask is one of the values
///      cache_file_new_flags_endian_unset, cache_file_new_flags_endian_invalid,
///      cache_file_new_flags_endian_little, cache_file_new_flags_endian_big.
///
///      The remaining bits are unused and should be generated as zero and
///      ignored by readers.  */
///   uint8_t flags;
///
///   uint8_t padding_unsed[3];	/* Not used, for future extensions.  */
///
///   /* File offset of the extension directory.  See struct
///      cache_extension below.  Must be a multiple of four.  */
///   uint32_t extension_offset;
///
///   uint32_t unused[3];		/* Leave space for future extensions
/// 				   and align to 8 byte boundary.  */
///   struct file_entry_new libs[0]; /* Entries describing libraries.  */
///   /* After this the string table of size len_strings is found.	*/
/// };
///```
/// As a side note, 5 was chosen because you have len_strings which was added compared to
/// the usual format so (5+1)*4=24 bytes or 3*8 bytes.
impl Cache {
    pub fn new() -> Result<Cache, CacheError> {
        let mut file = File::open(LD_SO_CACHE)?;
        let mut buf: Vec<u8> = Vec::new();
        if file.read_to_end(&mut buf)? == 0 {
            return Err(CacheError::InvalidSize(HEADER_LEN));
        }
        Self::parse(&*buf, TargetEndian::Native)
    }

    pub fn parse(buf: &[u8], endianness: TargetEndian) -> Result<Cache, CacheError> {
        let (mut cache, index) = Self::parse_struct(buf, endianness)?;
        cache.parse_entries(buf, index, endianness)?;
        Ok(cache)
    }

    fn parse_entries(
        &mut self,
        buf: &[u8],
        mut index: usize,
        endianness: TargetEndian,
    ) -> Result<(), CacheError> {
        let n = if self._is_old { 3 } else { 5 };
        if buf.len() < n * U32_SIZE * self.count as usize {
            return Err(CacheError::InvalidSize(n * U32_SIZE * self.count as usize));
        }
        let start_header = index + self.count as usize * U32_SIZE * n;
        for _ in 0..self.count {
            let flags: i32 = Self::read_i32(Self::get_next_4b_slice(buf, index, 0)?, &endianness);
            let key: u32 = Self::read_u32(Self::get_next_4b_slice(buf, index, 1)?, &endianness);
            let value: u32 = Self::read_u32(Self::get_next_4b_slice(buf, index, 2)?, &endianness);
            index += U32_SIZE * 3;
            let mut os_version: Option<u32> = None;
            let mut hwcap: Option<u64> = None;
            if !self._is_old {
                os_version = Some(Self::read_u32(
                    Self::get_next_4b_slice(buf, index, 0)?,
                    &endianness,
                ));
                hwcap = Some(Self::read_u64(
                    Self::get_next_8b_slice(buf, index + U32_SIZE, 0)?,
                    &endianness,
                ));
                index += U32_SIZE * 3;
            }
            let start = key as usize + if self._is_old { start_header } else { 0 };
            let libname = Self::str_from_u8_nul_utf8(&buf[start..]).map_err(|e| {
                CacheError::InvalidString {
                    index: start,
                    stream: Vec::from(&buf[start..std::cmp::min(buf.len(), start + 10)]),
                    error: e,
                }
            })?;
            let start = value as usize + if self._is_old { start_header } else { 0 };
            let path = Self::str_from_u8_nul_utf8(&buf[start..]).map_err(|e| {
                CacheError::InvalidString {
                    index: start,
                    stream: Vec::from(&buf[start..std::cmp::min(buf.len(), start + 10)]),
                    error: e,
                }
            })?;
            self.entries
                .entry(libname.to_string())
                .and_modify(|e| {
                    e.libname.push(libname.to_string());
                    e.path.push(path.to_string());
                })
                .or_insert(Entry {
                    flags,
                    libname: vec![libname.to_string()],
                    path: vec![path.to_string()],
                    key,
                    value,
                    os_version,
                    hwcap,
                });
        }
        Ok(())
    }

    pub fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
        let nul_range_end = utf8_src
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(utf8_src.len()); // default to length if no `\0` present
        ::std::str::from_utf8(&utf8_src[0..nul_range_end])
    }

    fn get_next_4b_slice(buf: &[u8], mut index: usize, offset: usize) -> Result<&[u8], CacheError> {
        index = index + offset * U32_SIZE;
        if buf.len() < index + U32_SIZE {
            return Err(CacheError::MissingSlice(index as u32));
        }
        Ok(&buf[index..index + U32_SIZE])
    }

    fn get_next_8b_slice(buf: &[u8], mut index: usize, offset: usize) -> Result<&[u8], CacheError> {
        index = index + offset * U64_SIZE;
        if buf.len() < index + U64_SIZE {
            return Err(CacheError::MissingSlice(index as u32));
        }
        Ok(&buf[index..index + U64_SIZE])
    }

    fn parse_struct(buf: &[u8], endianness: TargetEndian) -> Result<(Cache, usize), CacheError> {
        // parse header to know applicable logic
        let is_old: bool = Self::parse_header(&buf[..HEADER_LEN * U8_SIZE])?;
        let mut index: usize = if is_old {
            OLD_HEADER.len() * U8_SIZE
        } else {
            HEADER.len() * U8_SIZE
        };
        // assert length is enough to parse the full struct
        if is_old {
            if buf.len() < index + PADDING_OLD + U32_SIZE {
                return Err(CacheError::InvalidSize(index + U32_SIZE));
            }
        } else {
            if buf.len() < index + PADDING_NEW + VERSION_SIZE + U32_SIZE * 7 {
                return Err(CacheError::InvalidSize(
                    index + PADDING_NEW + VERSION_SIZE + U32_SIZE * 7,
                ));
            }
        }

        // parse version
        let version: &str = if !is_old {
            // parse the version numbers
            let version = &buf[index..index + VERSION_SIZE];
            index += VERSION_SIZE;
            index += PADDING_NEW;
            std::str::from_utf8(version).map_err(|e| CacheError::InvalidHeader {
                expected: format!("A correct version like {}", CURRENT_VERSION),
                found: format!("{:?} with error {}", version, e.to_string()),
            })?
        } else {
            index += PADDING_OLD;
            OLD_VERSION
        };
        // parse libraries count
        let count: u32 = Self::read_u32(&buf[index..index + U32_SIZE], &endianness);
        index += U32_SIZE;

        let mut strlen: Option<u32> = None;
        let mut flags: Option<u8> = None;
        let mut extension_offset: Option<u32> = None;
        if !is_old {
            // parse string table length
            strlen = Some(Self::read_u32(&buf[index..index + U32_SIZE], &endianness));
            index += U32_SIZE;
            flags = Some(*&buf[index]);
            // the 3 u8 here are unused
            index += U32_SIZE;
            extension_offset = Some(Self::read_u32(&buf[index..index + U32_SIZE], &endianness));
            index += U32_SIZE;
            for _ in 2..5 {
                let unused: u32 = Self::read_u32(&buf[index..index + U32_SIZE], &endianness);
                index += U32_SIZE;
                if unused != 0 {
                    eprintln!("format was slightly changed, we advise you to open an issue or look over your data.")
                }
            }
        }
        Ok((
            Cache {
                _is_old: is_old,
                version: version.to_string(),
                count,
                strlen,
                flags,
                extension_offset,
                entries: HashMap::with_capacity(count as usize),
            },
            index,
        ))
    }

    fn read_u32(buf: &[u8], endianness: &TargetEndian) -> u32 {
        let buf: [u8; 4] = <[u8; 4]>::try_from(&buf[..4]).unwrap();
        match endianness {
            TargetEndian::Native => u32::from_ne_bytes(buf),
            TargetEndian::Big => u32::from_be_bytes(buf),
            TargetEndian::Little => u32::from_le_bytes(buf),
        }
    }

    fn read_i32(buf: &[u8], endianness: &TargetEndian) -> i32 {
        let buf: [u8; 4] = <[u8; 4]>::try_from(&buf[..4]).unwrap();
        match endianness {
            TargetEndian::Native => i32::from_ne_bytes(buf),
            TargetEndian::Big => i32::from_be_bytes(buf),
            TargetEndian::Little => i32::from_le_bytes(buf),
        }
    }

    fn read_u64(buf: &[u8], endianness: &TargetEndian) -> u64 {
        let buf: [u8; 8] = <[u8; 8]>::try_from(&buf[..8]).unwrap();
        match endianness {
            TargetEndian::Native => u64::from_ne_bytes(buf),
            TargetEndian::Big => u64::from_be_bytes(buf),
            TargetEndian::Little => u64::from_le_bytes(buf),
        }
    }

    fn parse_header(buf: &[u8]) -> Result<bool, CacheError> {
        let mut is_old: bool = false;
        if let Ok(header) = std::str::from_utf8(&buf[..HEADER.len() * U8_SIZE]) {
            if header != HEADER {
                // technically here we should be fixed that the header is incorrect
                // since the old_header used to have a non parseable character inside the range
                is_old = true;
            }
        } else {
            is_old = true;
        }
        if is_old {
            let old_header: &str = std::str::from_utf8(&buf[..OLD_HEADER.len() * U8_SIZE])
                .map_err(|e| CacheError::InvalidHeader {
                    expected: OLD_HEADER.to_string(),
                    found: e.to_string(),
                })?;
            if old_header != OLD_HEADER {
                return Err(CacheError::InvalidHeader {
                    expected: format!("Either {} or {}", HEADER, OLD_HEADER),
                    found: old_header.to_string(),
                });
            }
        }
        Ok(is_old)
    }

    /// Utility function, does the contains check on the entries with the full lib name
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Utility function, get the entry based on the full lib name
    pub fn get(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Utility function, get the paths of the lib based on the full lib name
    pub fn get_paths(&self, key: &str) -> Option<Vec<&str>> {
        self.get(key)
            .map(|e| e.path.iter().map(|e| e.as_str()).collect())
    }

    /// Utility function, get the first path of the lib based on the full lib name
    pub fn get_path(&self, key: &str) -> Option<&str> {
        self.get(key)
            .and_then(|e| e.path.first().map(|x| x.as_str()))
    }

    /// Utility function, create an iterator over the entries
    pub fn iter(&self) -> Iter<'_, String, Entry> {
        self.entries.iter()
    }

    /// Utility function, return a boolean indicating if there is a partial match
    /// As this utility will iterate over all elements, if you need the element please
    /// use get_partial or get_path_partial
    pub fn contains_partial(&self, key: &str) -> bool {
        self.iter().any(|e| e.0.contains(key))
    }

    /// Utility function, return the first element that contains the key inside the full lib
    /// name (partial match)
    pub fn get_partial(&self, key: &str) -> Option<&Entry> {
        self.iter().find(|&e| e.0.contains(key)).map(|e| e.1)
    }

    /// Utility function, return the first lib paths for which the full lib
    /// name contains the key (partial match)
    pub fn get_paths_partial(&self, key: &str) -> Option<Vec<&str>> {
        self.get_partial(key)
            .map(|e| e.path.iter().map(|e| e.as_str()).collect())
    }

    /// Utility function, return the first lib path for which the full lib
    /// name contains the key (partial match)
    pub fn get_path_partial(&self, key: &str) -> Option<&str> {
        self.get_partial(key)
            .and_then(|e| e.path.first().map(|x| x.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_endian_old_format_s390x() {
        let data = include_bytes!("../tests/ld.so.cache_s390x_old");
        let cache = Cache::parse(data, TargetEndian::Big);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.count, 188);
        assert_eq!(cache.version, OLD_VERSION);
        assert_eq!(cache._is_old, true);
        assert_eq!(cache.strlen, None);
        assert_eq!(cache.flags, None);
        assert_eq!(cache.extension_offset, None);
        let strings: &str = include_str!("../tests/s390x.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_new_format_mips() {
        let data = include_bytes!("../tests/ld.so.cache_mips");
        let cache = Cache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.count, 2407);
        assert_eq!(cache.version, CURRENT_VERSION);
        assert_eq!(cache._is_old, false);
        assert_eq!(cache.strlen, Some(60915));
        assert_eq!(cache.flags, Some(2)); // little endian
        assert_eq!(cache.extension_offset, Some(118732));
        let strings: &str = include_str!("../tests/mips.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_new_format_debian_x86_64() {
        let data = include_bytes!("../tests/ld.so.cache_debian");
        let cache = Cache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.count, 81);
        assert_eq!(cache.version, CURRENT_VERSION);
        assert_eq!(cache._is_old, false);
        assert_eq!(cache.strlen, Some(4188));
        assert_eq!(cache.flags, Some(2)); // little endian
        assert_eq!(cache.extension_offset, Some(0));
        let strings: &str = include_str!("../tests/debian.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_old_format_debian_x86_64() {
        let data = include_bytes!("../tests/ld.so.cache_debian_old");
        let cache = Cache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.count, 148);
        assert_eq!(cache.version, OLD_VERSION);
        assert_eq!(cache._is_old, true);
        assert_eq!(cache.strlen, None);
        assert_eq!(cache.flags, None);
        assert_eq!(cache.extension_offset, None);
        let strings: &str = include_str!("../tests/debian_old.strings");
        test_entries(strings, cache);
    }

    fn test_entries(strings: &str, cache: Cache) {
        for string in strings.split_terminator("\n") {
            let (lib_name, path) = string.split_once(" ").unwrap();
            assert!(
                cache.contains(lib_name),
                "lib name : {} was not inside the entries",
                lib_name
            );
            let found_paths = cache.get_paths(lib_name);
            assert!(
                found_paths.is_some(),
                "Path was not found for lib name : {}",
                lib_name
            );
            let found_paths = found_paths.unwrap();
            assert!(
                found_paths.contains(&path),
                "lib path : {} was not correct, got {:?}",
                path,
                found_paths
            );
        }
    }
}
