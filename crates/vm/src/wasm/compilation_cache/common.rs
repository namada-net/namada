//! WASM compilation cache.
//!
//! The cache is backed by in-memory LRU cache with configurable size
//! limit and a file system cache of serialized modules.

use std::collections::hash_map::RandomState;
use std::fs;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::Duration;

use clru::{CLruCache, CLruCacheConfig, WeightScale};
use namada_core::collections::HashMap;
use namada_core::control_flow::time::{ExponentialBackoff, SleepStrategy};
use namada_core::hash::Hash;
use namada_gas::GasMeterKind;
use wasmer::{Module, Store};
use wasmer_cache::{FileSystemCache, Hash as CacheHash};

use crate::wasm::run::untrusted_wasm_store;
use crate::wasm::{self, memory};
use crate::{WasmCacheAccess, WasmCacheRoAccess};

/// Cache handle. Thread-safe.
#[derive(Debug, Clone)]
pub struct Cache<N, A> {
    /// Cached files directory
    dir: PathBuf,
    /// Compilation progress
    progress: Arc<RwLock<HashMap<CacheKey, Compilation>>>,
    /// In-memory LRU cache of compiled modules
    in_memory: Arc<RwLock<MemoryCache>>,
    /// The cache's name
    name: PhantomData<N>,
    /// Cache access level
    access: PhantomData<A>,
    /// Wasmer store - The store that's used to compile the modules.
    // N.B.: This has to be kept alive to avoid segfaults when running them
    // from cache (otherwise `wasmer_compiler::FRAME_INFO` gets cleared out
    // when the `Store` is dropped and the next run of this `Module`
    // doesn't re-instantiate it and crashes when it tries to access it).
    // Related issues:
    // - https://github.com/wasmerio/wasmer/issues/4377
    // - https://github.com/wasmerio/wasmer/issues/4949
    store: Arc<Store>,
}

/// This trait is used to give names to different caches
pub trait CacheName: Clone + std::fmt::Debug {
    /// Get the name of the cache
    fn name() -> &'static str;
}

/// WASM cache key consists of the code hash and gas meter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    code_hash: Hash,
    gas_meter_kind: GasMeterKind,
}

/// In-memory LRU cache of compiled modules
type MemoryCache = CLruCache<CacheKey, Module, RandomState, ModuleCacheScale>;

/// Compilation progress
#[derive(Debug)]
enum Compilation {
    Compiling,
    Done,
}

/// Configures the cache scale of modules that limits the maximum capacity
/// of the cache (CLruCache::len + CLruCache::weight <= CLruCache::capacity).
#[derive(Debug)]
struct ModuleCacheScale;

impl WeightScale<CacheKey, Module> for ModuleCacheScale {
    fn weight(&self, _key: &CacheKey, _value: &Module) -> usize {
        1
    }
}

impl<N: CacheName, A: WasmCacheAccess> Cache<N, A> {
    /// Create a wasm in-memory cache with a given size limit and a file
    /// system cache.
    ///
    /// # Panics
    /// The `max_bytes` must be non-zero.
    pub fn new(dir: impl Into<PathBuf>, max_bytes: usize) -> Self {
        let cache = CLruCache::with_config(
            CLruCacheConfig::new(NonZeroUsize::new(max_bytes).unwrap())
                .with_scale(ModuleCacheScale),
        );
        let in_memory = Arc::new(RwLock::new(cache));

        let target_hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::hash::DefaultHasher::new();
            wasmer::Target::default().hash(&mut hasher);
            hasher.finish()
        };
        let version = format!(
            "{}_{:x}",
            concat!(env!("CARGO_PKG_VERSION"), "_", env!("RUSTUP_TOOLCHAIN")),
            target_hash,
        );
        let dir = dir.into().join(version);

        fs::create_dir_all(&dir)
            .expect("Couldn't create the wasm cache directory");

        Self {
            dir,
            progress: Default::default(),
            in_memory,
            name: Default::default(),
            access: Default::default(),
            store: Arc::new(store()),
        }
    }

    /// Get a WASM module from LRU cache, from a file or compile it and cache
    /// it. If the cache access is set to [`crate::WasmCacheRwAccess`], it
    /// updates the position in the LRU cache. Otherwise, the compiled
    /// module will not be cached, if it's not already.
    pub fn fetch(
        &mut self,
        code_hash: &Hash,
        gas_meter_kind: GasMeterKind,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        if A::is_read_write() {
            let module = self.get(code_hash, gas_meter_kind)?;
            Ok(module.map(|module| (module, store())))
        } else {
            let store = store();
            let module = self.peek(code_hash, gas_meter_kind, &store)?;
            Ok(module.map(|module| (module, store)))
        }
    }

    /// Get the current number of items in the cache
    pub fn get_size(&self) -> usize {
        self.in_memory.read().unwrap().len()
    }

    /// Get the current weight of the cache
    pub fn get_cache_size(&self) -> usize {
        self.in_memory.read().unwrap().weight()
    }

    /// Get a WASM module from LRU cache, from a file or compile it and cache
    /// it. Updates the position in the LRU cache.
    fn get(
        &mut self,
        hash: &Hash,
        gas_meter_kind: GasMeterKind,
    ) -> Result<Option<Module>, wasm::run::Error> {
        let key = CacheKey {
            code_hash: *hash,
            gas_meter_kind,
        };
        let mut in_memory = self.in_memory.write().unwrap();
        if let Some(module) = in_memory.get(&key) {
            tracing::trace!(
                "{} found {} in cache.",
                N::name(),
                hash.to_string()
            );
            return Ok(Some(module.clone()));
        }
        drop(in_memory);

        let mut iter = 0;
        let exponential_backoff = ExponentialBackoff {
            base: 2,
            as_duration: |backoff: u64| {
                Duration::from_millis(backoff.saturating_mul(10))
            },
        };
        loop {
            let progress = self.progress.read().unwrap();
            match progress.get(&key) {
                Some(Compilation::Done) => {
                    drop(progress);
                    let mut in_memory = self.in_memory.write().unwrap();
                    if let Some(module) = in_memory.get(&key) {
                        tracing::info!(
                            "{} found {} in memory cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some(module.clone()));
                    }

                    if let Ok(module) = file_load_module(
                        &self.dir,
                        hash,
                        gas_meter_kind,
                        &self.store,
                    ) {
                        tracing::info!(
                            "{} found {} in file cache.",
                            N::name(),
                            hash.to_string()
                        );
                        // Put into cache, ignore result if it's full
                        let _ = in_memory.put_with_weight(key, module.clone());

                        return Ok(Some(module));
                    } else {
                        return Ok(None);
                    }
                }
                Some(Compilation::Compiling) => {
                    drop(progress);
                    tracing::info!(
                        "Waiting for {} {} ...",
                        N::name(),
                        hash.to_string()
                    );
                    sleep(exponential_backoff.backoff(&iter));
                    // Cannot overflow
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        iter += 1;
                    }
                    continue;
                }
                None => {
                    drop(progress);
                    let module = if module_file_exists(
                        &self.dir,
                        hash,
                        gas_meter_kind,
                    ) {
                        tracing::info!(
                            "Trying to load {} {} from file.",
                            N::name(),
                            hash.to_string()
                        );
                        if let Ok(module) = file_load_module(
                            &self.dir,
                            hash,
                            gas_meter_kind,
                            &self.store,
                        ) {
                            module
                        } else {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    };

                    // Update progress
                    let mut progress = self.progress.write().unwrap();
                    progress.insert(key, Compilation::Done);

                    // Put into cache, ignore the result (fails if the module
                    // cannot fit into the cache)
                    let mut in_memory = self.in_memory.write().unwrap();
                    let _ = in_memory.put_with_weight(key, module.clone());

                    return Ok(Some(module));
                }
            }
        }
    }

    /// Peak-only is used for dry-ran txs (and VPs that the tx triggers).
    /// It doesn't update the in-memory cache.
    fn peek(
        &self,
        hash: &Hash,
        gas_meter_kind: GasMeterKind,
        store: &Store,
    ) -> Result<Option<Module>, wasm::run::Error> {
        let key = CacheKey {
            code_hash: *hash,
            gas_meter_kind,
        };
        let in_memory = self.in_memory.read().unwrap();
        if let Some(module) = in_memory.peek(&key) {
            tracing::info!(
                "{} found {} in cache.",
                N::name(),
                hash.to_string()
            );
            return Ok(Some(module.clone()));
        }
        drop(in_memory);

        let mut iter = 0;
        let exponential_backoff = ExponentialBackoff {
            base: 2,
            as_duration: |backoff: u64| {
                Duration::from_millis(backoff.saturating_mul(10))
            },
        };
        loop {
            let progress = self.progress.read().unwrap();
            match progress.get(&key) {
                Some(Compilation::Done) => {
                    drop(progress);
                    let in_memory = self.in_memory.read().unwrap();
                    if let Some(module) = in_memory.peek(&key) {
                        tracing::info!(
                            "{} found {} in memory cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some(module.clone()));
                    }

                    if let Ok(module) =
                        file_load_module(&self.dir, hash, gas_meter_kind, store)
                    {
                        tracing::info!(
                            "{} found {} in file cache.",
                            N::name(),
                            hash.to_string()
                        );
                        return Ok(Some(module));
                    } else {
                        return Ok(None);
                    }
                }
                Some(Compilation::Compiling) => {
                    drop(progress);
                    tracing::info!(
                        "Waiting for {} {} ...",
                        N::name(),
                        hash.to_string()
                    );
                    sleep(exponential_backoff.backoff(&iter));
                    // Cannot overflow
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        iter += 1;
                    }
                    continue;
                }
                None => {
                    drop(progress);

                    return if module_file_exists(
                        &self.dir,
                        hash,
                        gas_meter_kind,
                    ) {
                        tracing::info!(
                            "Trying to load {} {} from file.",
                            N::name(),
                            hash.to_string()
                        );
                        if let Ok(module) = file_load_module(
                            &self.dir,
                            hash,
                            gas_meter_kind,
                            store,
                        ) {
                            return Ok(Some(module));
                        } else {
                            return Ok(None);
                        }
                    } else {
                        Ok(None)
                    };
                }
            }
        }
    }

    /// Compile a WASM module and persist the compiled modules to files.
    pub fn compile_or_fetch(
        &mut self,
        code: impl AsRef<[u8]>,
        gas_meter_kind: GasMeterKind,
    ) -> Result<Option<(Module, Store)>, wasm::run::Error> {
        let hash = hash_of_code(&code);
        let key = CacheKey {
            code_hash: hash,
            gas_meter_kind,
        };

        if !A::is_read_write() {
            // It doesn't update the cache and files
            let progress = self.progress.read().unwrap();
            match progress.get(&key) {
                Some(_) => {
                    let store = store();
                    let module = self.peek(&hash, gas_meter_kind, &store)?;
                    return Ok(module.map(|module| (module, store)));
                }
                None => {
                    let code =
                        wasm::run::prepare_wasm_code(code, gas_meter_kind)?;
                    let store = store();
                    let module = compile(code, &store)?;
                    return Ok(Some((module, store)));
                }
            }
        }

        let mut progress = self.progress.write().unwrap();
        if progress.get(&key).is_some() {
            drop(progress);
            return self.fetch(&hash, gas_meter_kind);
        }
        progress.insert(key, Compilation::Compiling);
        drop(progress);

        tracing::info!("Compiling {} {}.", N::name(), hash.to_string());

        match wasm::run::prepare_wasm_code(code, gas_meter_kind) {
            Ok(code) => {
                file_write_code(&self.dir, &code, &hash);

                match compile(code, &self.store) {
                    Ok(module) => {
                        // Write the file
                        file_write_module(
                            &self.dir,
                            &module,
                            &hash,
                            gas_meter_kind,
                        );

                        // Update progress
                        let mut progress = self.progress.write().unwrap();
                        progress.insert(key, Compilation::Done);

                        // Put into cache, ignore result if it's full
                        let mut in_memory = self.in_memory.write().unwrap();
                        let _ = in_memory.put_with_weight(
                            CacheKey {
                                code_hash: hash,
                                gas_meter_kind,
                            },
                            module.clone(),
                        );

                        Ok(Some((module, store())))
                    }
                    Err(err) => {
                        tracing::info!(
                            "Failed to compile WASM {} with {}",
                            hash.to_string(),
                            err
                        );
                        let mut progress = self.progress.write().unwrap();
                        progress.swap_remove(&key);
                        Err(err)
                    }
                }
            }
            Err(err) => {
                tracing::info!(
                    "Failed to prepare WASM {} with {}",
                    hash.to_string(),
                    err
                );
                let mut progress = self.progress.write().unwrap();
                progress.swap_remove(&key);
                Err(err)
            }
        }
    }

    /// Pre-compile a WASM module to a file. The compilation runs in a new OS
    /// thread and the function returns immediately.
    pub fn pre_compile(
        &mut self,
        code: impl AsRef<[u8]>,
        gas_meter_kind: GasMeterKind,
    ) {
        if A::is_read_write() {
            let hash = hash_of_code(&code);
            let key = CacheKey {
                code_hash: hash,
                gas_meter_kind,
            };
            let mut progress = self.progress.write().unwrap();
            match progress.get(&key) {
                Some(_) => {
                    // Already known, do nothing
                }
                None => {
                    if module_file_exists(&self.dir, &hash, gas_meter_kind) {
                        progress.insert(key, Compilation::Done);
                        return;
                    }
                    progress.insert(key, Compilation::Compiling);
                    drop(progress);
                    let progress = self.progress.clone();
                    let code = code.as_ref().to_vec();
                    let dir = self.dir.clone();
                    let store = self.store.clone();
                    std::thread::spawn(move || {
                        tracing::info!("Compiling WASM {}.", hash.to_string());

                        let _module = match wasm::run::prepare_wasm_code(
                            code,
                            gas_meter_kind,
                        ) {
                            Ok(code) => {
                                file_write_code(&dir, &code, &hash);

                                match compile(code, &store) {
                                    Ok(module) => {
                                        // Write the file
                                        file_write_module(
                                            &dir,
                                            &module,
                                            &hash,
                                            gas_meter_kind,
                                        );

                                        // Update progress
                                        let mut progress =
                                            progress.write().unwrap();
                                        progress.insert(key, Compilation::Done);
                                        tracing::info!(
                                            "Finished compiling WASM {hash}."
                                        );
                                        if progress.values().all(
                                            |compilation| {
                                                matches!(
                                                    compilation,
                                                    Compilation::Done
                                                )
                                            },
                                        ) {
                                            tracing::info!(
                                                "Finished compiling all {}.",
                                                N::name()
                                            )
                                        }
                                        module
                                    }
                                    Err(err) => {
                                        let mut progress =
                                            progress.write().unwrap();
                                        tracing::info!(
                                            "Failed to compile WASM {} with {}",
                                            hash.to_string(),
                                            err
                                        );
                                        progress.swap_remove(&key);
                                        return Err(err);
                                    }
                                }
                            }
                            Err(err) => {
                                let mut progress = progress.write().unwrap();
                                tracing::info!(
                                    "Failed to prepare WASM {} with {}",
                                    hash.to_string(),
                                    err
                                );
                                progress.swap_remove(&key);
                                return Err(err);
                            }
                        };

                        let res: Result<(), wasm::run::Error> = Ok(());
                        res
                    });
                }
            }
        }
    }

    /// Get a read-only cache handle.
    pub fn read_only(&self) -> Cache<N, WasmCacheRoAccess> {
        Cache {
            dir: self.dir.clone(),
            progress: self.progress.clone(),
            in_memory: self.in_memory.clone(),
            name: Default::default(),
            access: Default::default(),
            store: self.store.clone(),
        }
    }
}

fn hash_of_code(code: impl AsRef<[u8]>) -> Hash {
    Hash::sha256(code.as_ref())
}

fn compile(
    code: impl AsRef<[u8]>,
    store: &Store,
) -> Result<Module, wasm::run::Error> {
    universal::compile(code, store).map_err(wasm::run::Error::CompileError)
}

fn file_ext() -> &'static str {
    // This has to be using the file_ext matching the compilation method in the
    // `fn compile`
    universal::FILE_EXT
}

pub(crate) fn store() -> Store {
    // This has to be using the store matching the compilation method in the
    // `fn compile`
    universal::store()
}

fn file_write_module(
    dir: impl AsRef<Path>,
    module: &Module,
    hash: &Hash,
    gas_meter_kind: GasMeterKind,
) {
    use wasmer_cache::Cache;
    let mut fs_cache = fs_cache(dir, hash, gas_meter_kind);
    fs_cache.store(CacheHash::new(hash.0), module).unwrap();
}

fn file_write_code(dir: &Path, code: &[u8], hash: &Hash) {
    store_code(dir, CacheHash::new(hash.0), code);
}

fn store_code(dir: &Path, key: CacheHash, code: &[u8]) {
    let filename = format!("{}.{}", key, ".wasm");
    let path = dir.join(filename);
    let mut file = fs::File::create(path).unwrap();
    std::io::Write::write_all(&mut file, code).unwrap()
}

fn file_load_module(
    dir: impl AsRef<Path>,
    hash: &Hash,
    gas_meter_kind: GasMeterKind,
    store: &Store,
) -> Result<Module, wasmer::DeserializeError> {
    use wasmer_cache::Cache;
    let fs_cache = fs_cache(dir, hash, gas_meter_kind);
    let hash = CacheHash::new(hash.0);
    let module = unsafe { fs_cache.load(store, hash) };
    if let Err(err) = module.as_ref() {
        tracing::error!(
            "Error loading cached wasm {}: {err}.",
            hash.to_string()
        );
    }
    module
}

fn fs_cache(
    dir: impl AsRef<Path>,
    hash: &Hash,
    gas_meter_kind: GasMeterKind,
) -> FileSystemCache {
    let kind = gas_meter_kind_dir(gas_meter_kind);
    let path = dir
        .as_ref()
        .join(kind)
        .join(hash.to_string().to_lowercase());
    let mut fs_cache = FileSystemCache::new(path).unwrap();
    fs_cache.set_cache_extension(Some(file_ext()));
    fs_cache
}

fn gas_meter_kind_dir(gas_meter_kind: GasMeterKind) -> &'static str {
    match gas_meter_kind {
        GasMeterKind::HostFn => "host_fn",
        GasMeterKind::MutGlobal => "mut_global",
    }
}

fn module_file_exists(
    dir: impl AsRef<Path>,
    hash: &Hash,
    gas_meter_kind: GasMeterKind,
) -> bool {
    let file = dir
        .as_ref()
        .join(gas_meter_kind_dir(gas_meter_kind))
        .join(hash.to_string().to_lowercase())
        .join(format!(
            "{}.{}",
            hash.to_string().to_lowercase(),
            file_ext()
        ));
    file.exists()
}

/// A universal engine compilation. The module can be serialized to/from bytes.
mod universal {
    use super::*;

    #[allow(dead_code)]
    pub const FILE_EXT: &str = "bin";

    /// Compile wasm with a universal engine.
    #[allow(dead_code)]
    pub fn compile(
        code: impl AsRef<[u8]>,
        store: &Store,
    ) -> Result<Module, wasmer::CompileError> {
        Module::new(store, code.as_ref())
    }

    /// Universal WASM store
    #[allow(dead_code)]
    pub fn store() -> Store {
        untrusted_wasm_store(memory::vp_limit())
    }
}

/// Testing helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::WasmCacheRwAccess;
    use crate::wasm::{TxCache, VpCache};

    /// Instantiate the default wasmer store.
    pub fn store() -> Store {
        super::store()
    }

    /// VP Cache with a temp dir for testing
    pub fn vp_cache() -> (VpCache<WasmCacheRwAccess>, TempDir) {
        cache::<super::super::vp::Name>()
    }

    /// Tx Cache with a temp dir for testing
    pub fn tx_cache() -> (TxCache<WasmCacheRwAccess>, TempDir) {
        cache::<super::super::tx::Name>()
    }

    /// Generic Cache with a temp dir for testing
    pub fn cache<N: CacheName>() -> (Cache<N, WasmCacheRwAccess>, TempDir) {
        let dir = tempdir().unwrap();
        let cache = Cache::new(
            dir.path(),
            50 * 1024 * 1024, // 50 MiB
        );
        (cache, dir)
    }
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod test {
    use std::cmp::max;

    use assert_matches::assert_matches;
    use byte_unit::{Byte, UnitType};
    use namada_test_utils::TestWasms;
    use tempfile::{TempDir, tempdir};
    use test_log::test;

    use super::*;
    use crate::WasmCacheRwAccess;

    #[test]
    fn test_fetch_or_compile_valid_wasm() {
        // Load some WASMs and find their hashes and in-memory size
        let tx_read_storage_key = load_wasm(TestWasms::TxReadStorageKey.path());
        let tx_no_op = load_wasm(TestWasms::TxNoOp.path());
        let gas_meter_kind = GasMeterKind::MutGlobal;
        // Create a new cache with the limit set to
        // `max(tx_read_storage_key.size, tx_no_op.size) + 1`
        {
            let max_bytes = max(tx_read_storage_key.size, tx_no_op.size) + 1;
            println!(
                "Using cache with max_bytes {} ({})",
                Byte::from_u128(max_bytes as u128)
                    .unwrap()
                    .get_appropriate_unit(UnitType::Binary),
                max_bytes
            );
            let (mut cache, _tmp_dir) = cache(max_bytes);

            // Fetch `tx_read_storage_key`
            {
                let fetched = cache
                    .fetch(&tx_read_storage_key.hash, gas_meter_kind)
                    .unwrap();
                assert_matches!(
                    fetched,
                    None,
                    "The module should not be in cache"
                );

                let fetched = cache
                    .compile_or_fetch(
                        &tx_read_storage_key.code,
                        GasMeterKind::MutGlobal,
                    )
                    .unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The code should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_read_storage_key.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
            }

            // Fetch `tx_no_op`. Fetching another module should get us over the
            // limit, so the previous one should be popped from the cache
            {
                let fetched =
                    cache.fetch(&tx_no_op.hash, gas_meter_kind).unwrap();
                assert_matches!(
                    fetched,
                    None,
                    "The module must not be in cache"
                );

                let fetched = cache
                    .compile_or_fetch(&tx_no_op.code, GasMeterKind::MutGlobal)
                    .unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The code should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_no_op.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: tx_no_op.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_no_op.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_read_storage_key.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Reset the in-memory cache and progress and fetch
            // `tx_read_storage_key` again, this time it should get loaded
            // from file
            let in_memory_cache = CLruCache::with_config(
                CLruCacheConfig::new(NonZeroUsize::new(max_bytes).unwrap())
                    .with_scale(ModuleCacheScale),
            );
            let in_memory = Arc::new(RwLock::new(in_memory_cache));
            cache.in_memory = in_memory;
            cache.progress = Default::default();
            {
                let fetched = cache
                    .fetch(&tx_read_storage_key.hash, gas_meter_kind)
                    .unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in file cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_read_storage_key.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_no_op.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_no_op.hash,
                        gas_meter_kind
                    }),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Fetch `tx_read_storage_key` again, now it should be in-memory
            {
                let fetched = cache
                    .fetch(&tx_read_storage_key.hash, gas_meter_kind)
                    .unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in memory"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_read_storage_key.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(
                        &cache.dir,
                        &tx_no_op.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_no_op.hash,
                        gas_meter_kind
                    }),
                    None,
                    "The module should have been popped from memory"
                );
            }

            // Fetch `tx_no_op` with read/only access
            {
                let mut cache = cache.read_only();

                let fetched =
                    cache.fetch(&tx_no_op.hash, gas_meter_kind).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                // Fetching with read-only should not modify the in-memory cache
                let fetched = cache
                    .compile_or_fetch(&tx_no_op.code, gas_meter_kind)
                    .unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module should be compiled"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_no_op.hash,
                        gas_meter_kind
                    }),
                    None,
                    "The module should not be added back to in-memory cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: tx_read_storage_key.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The previous module must still be in memory"
                );
            }
        }
    }

    #[test]
    fn test_fetch_or_compile_invalid_wasm() {
        // Some random bytes
        let invalid_wasm = vec![1_u8, 0, 8, 10, 6, 1];
        let hash = hash_of_code(&invalid_wasm);
        let gas_meter_kind = GasMeterKind::HostFn;
        let (mut cache, _) = testing::cache::<TestCache>();

        // Try to compile it
        let error = cache
            .compile_or_fetch(&invalid_wasm, GasMeterKind::MutGlobal)
            .expect_err("Compilation should fail");
        println!("Error: {}", error);

        let in_memory = cache.in_memory.read().unwrap();
        assert_matches!(
            in_memory.peek(&CacheKey {
                code_hash: hash,
                gas_meter_kind
            }),
            None,
            "There should be no entry for this hash in memory"
        );

        let progress = cache.progress.read().unwrap();
        assert_matches!(
            progress.get(&CacheKey {
                code_hash: hash,
                gas_meter_kind
            }),
            None,
            "Any progress is removed"
        );

        assert!(
            !module_file_exists(&cache.dir, &hash, gas_meter_kind),
            "The file must not be written"
        );
    }

    #[test]
    fn test_pre_compile_valid_wasm() {
        // Load some WASMs and find their hashes and in-memory size
        let vp_always_true = load_wasm(TestWasms::VpAlwaysTrue.path());
        let vp_eval = load_wasm(TestWasms::VpEval.path());

        // Create a new cache with the limit set to
        // `max(vp_always_true.size, vp_eval.size) + 1 + extra_bytes`
        {
            let max_bytes = max(vp_always_true.size, vp_eval.size) + 1;
            println!(
                "Using cache with max_bytes {} ({})",
                Byte::from_u128(max_bytes as u128)
                    .unwrap()
                    .get_appropriate_unit(UnitType::Binary),
                max_bytes
            );
            let (mut cache, _tmp_dir) = cache(max_bytes);
            let gas_meter_kind = GasMeterKind::MutGlobal;

            // Pre-compile `vp_always_true`
            {
                cache
                    .pre_compile(&vp_always_true.code, GasMeterKind::MutGlobal);

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: vp_always_true.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done | Compilation::Compiling),
                    "The progress must be updated"
                );
            }

            // Now fetch it to wait for it finish compilation
            {
                let fetched =
                    cache.fetch(&vp_always_true.hash, gas_meter_kind).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: vp_always_true.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: vp_always_true.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done),
                    "The progress must be updated"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &vp_always_true.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
            }

            // Pre-compile `vp_eval`. Pre-compiling another module should get us
            // over the limit, so the previous one should be popped
            // from the cache
            {
                cache.pre_compile(&vp_eval.code, GasMeterKind::MutGlobal);

                let progress = cache.progress.read().unwrap();
                assert_matches!(
                    progress.get(&CacheKey {
                        code_hash: vp_eval.hash,
                        gas_meter_kind
                    }),
                    Some(Compilation::Done | Compilation::Compiling),
                    "The progress must be updated"
                );
            }

            // Now fetch it to wait for it finish compilation
            {
                let fetched =
                    cache.fetch(&vp_eval.hash, gas_meter_kind).unwrap();
                assert_matches!(
                    fetched,
                    Some(_),
                    "The module must be in cache"
                );

                let in_memory = cache.in_memory.read().unwrap();
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: vp_eval.hash,
                        gas_meter_kind
                    }),
                    Some(_),
                    "The module must be in memory"
                );

                assert!(
                    module_file_exists(
                        &cache.dir,
                        &vp_eval.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );

                // The previous module's file should still exist
                assert!(
                    module_file_exists(
                        &cache.dir,
                        &vp_always_true.hash,
                        gas_meter_kind
                    ),
                    "The file must be written"
                );
                // But it should not be in-memory
                assert_matches!(
                    in_memory.peek(&CacheKey {
                        code_hash: vp_always_true.hash,
                        gas_meter_kind
                    }),
                    None,
                    "The module should have been popped from memory"
                );
            }
        }
    }

    #[test]
    fn test_pre_compile_invalid_wasm() {
        // Some random bytes
        let invalid_wasm = vec![1_u8];
        let hash = hash_of_code(&invalid_wasm);
        let (mut cache, _) = testing::cache::<TestCache>();
        let gas_meter_kind = GasMeterKind::HostFn;

        // Try to pre-compile it
        {
            cache.pre_compile(&invalid_wasm, GasMeterKind::MutGlobal);
            let progress = cache.progress.read().unwrap();
            assert_matches!(
                progress.get(&CacheKey {
                    code_hash: hash,
                    gas_meter_kind
                }),
                Some(Compilation::Done | Compilation::Compiling) | None,
                "The progress must be updated"
            );
        }

        // Now fetch it to wait for it finish compilation
        {
            let fetched = cache.fetch(&hash, gas_meter_kind).unwrap();
            assert_matches!(
                fetched,
                None,
                "There should be no entry for this hash in cache"
            );

            let in_memory = cache.in_memory.read().unwrap();
            assert_matches!(
                in_memory.peek(&CacheKey {
                    code_hash: hash,
                    gas_meter_kind
                }),
                None,
                "There should be no entry for this hash in memory"
            );

            let progress = cache.progress.read().unwrap();
            assert_matches!(
                progress.get(&CacheKey {
                    code_hash: hash,
                    gas_meter_kind
                }),
                None,
                "Any progress is removed"
            );

            assert!(
                !module_file_exists(&cache.dir, &hash, gas_meter_kind),
                "The file must not be written"
            );
        }
    }

    /// Get the WASM code bytes, its hash and find the compiled module's size
    fn load_wasm(file: impl AsRef<Path>) -> WasmWithMeta {
        let file = file.as_ref();
        let code = fs::read(file).unwrap();
        let hash = hash_of_code(&code);
        // Find the size of the compiled module
        let size = {
            let (mut cache, _tmp_dir) = cache(
                // No in-memory cache needed, but must be non-zero
                1,
            );
            let (_module, _store) = cache
                .compile_or_fetch(&code, GasMeterKind::MutGlobal)
                .unwrap()
                .unwrap();
            1
        };
        println!(
            "Compiled module {} size including the hash: {} ({})",
            file.to_string_lossy(),
            Byte::from_u128(size as u128)
                .unwrap()
                .get_appropriate_unit(UnitType::Binary),
            size,
        );
        WasmWithMeta { code, hash, size }
    }

    /// A test helper for loading WASM and finding its hash and size
    #[derive(Clone, Debug)]
    struct WasmWithMeta {
        code: Vec<u8>,
        hash: Hash,
        /// Compiled module's in-memory size
        size: usize,
    }

    /// A `CacheName` implementation for unit tests
    #[derive(Clone, Debug)]
    struct TestCache;
    impl CacheName for TestCache {
        fn name() -> &'static str {
            "test"
        }
    }

    /// A cache with a temp dir for unit tests
    fn cache(
        max_bytes: usize,
    ) -> (Cache<TestCache, WasmCacheRwAccess>, TempDir) {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path(), max_bytes);
        (cache, dir)
    }
}
