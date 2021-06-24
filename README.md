# ld_cache_rs
A simple parser for ld.so.cache in rust without any c bindings

Library to parse ld.so.cache according to the numerous format define in glibc
This library doesn't use any c bindings or doesn't try to create a structure to match
it over the data, it uses plain parsing and thus allow the definition of endianness.
As parsing ld.so.cache is useful to get access to the symbol, the parsing is done
stringently as well as fastly.
If you want to make a dirt cheap parser for ld.so.cache a simple call to
`strings /etc/ld.so.cache` will do.

## Usage

You usually want to load the default cache (/etc/ld.so.cache) with `Cache::new()`, however if you need to load a file
and not the default one, we do support that with  `Cache::parse(buf: &[u8], endianness: TargetEndian)` where the
endianness is one of the 3 values, Big, Little and Native.

```rust
use ldcache_rs::{Cache, CacheError, Entry};
use std::collections::hash_map::Iter;
fn main(){
    /// parse /etc/ld.so.cache with Native Endianness
    let cache:Result<Cache,CacheError>=Cache::new();
    let cache=cache.unwrap();
    /// Utility function, does the contains check on the entries with the full lib name
    let ok:bool=cache.contains("key");
    /// Utility function, get the entry based on the full lib name
    let entry:Option<&Entry>=cache.get("key");
    /// Utility function, get the paths of the lib based on the full lib name
    let paths:Option<Vec<&str>>=cache.get_paths("key");
    /// Utility function, get the first path of the lib based on the full lib name
    let path:Option<&str>=cache.get_path("key");
    /// Utility function, create an iterator over the entries
    let iter:Iter<'_, String, Entry>=cache.iter();
    /// Utility function, return a boolean indicating if there is a partial match
    /// As this utility will iterate over all elements, if you need the element please
    /// use get_partial or get_path_partial
    let ok_partial:bool=cache.contains_partial("key");
    /// Utility function, return the first element that contains the key inside the full lib
    /// name (partial match)
    let entry_partial:Option<&Entry>=cache.get_partial("key");
    /// Utility function, return the first lib paths for which the full lib
    /// name contains the key (partial match)
    let paths_partial:Option<Vec<&str>>=cache.get_paths_partial("key");
    /// Utility function, return the first lib path for which the full lib
    /// name contains the key (partial match)
    let path_partial:Option<&str>=cache.get_path_partial("key");
}
```
