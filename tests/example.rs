use ldcache_rs::{Cache, CacheError};

#[test]
fn load_default() -> Result<(), CacheError> {
    let cache = Cache::new()?;
    if cache.contains_partial("ld-linux") {
        let entry = cache.get_partial("ld-linux").unwrap();
        let full_name = entry.libname.first().unwrap();
        let not_partial = cache.get(full_name);
        assert!(not_partial.is_some());
        let paths = cache.get_paths(full_name);
        assert!(paths.is_some());
        let path = cache.get_path(full_name);
        assert!(path.is_some());
        dbg!(paths, path, not_partial);
    }

    Ok(())
}
