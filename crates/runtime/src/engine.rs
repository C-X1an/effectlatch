//! A fresh engine and store per invocation. The worker supervisor provides the
//! outer process deadline; epochs interrupt guest code executing in Wasmtime.
use effectlatch_domain::Limits;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use thiserror::Error;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

use crate::validate::{self, InvalidModule};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid runtime limits")]
    Limits(#[from] effectlatch_domain::ConfigError),
    #[error("invalid module")]
    InvalidModule(#[from] InvalidModule),
    #[error("Wasm engine or invocation failed")]
    Wasmtime(#[from] wasmtime::Error),
    #[error("could not start epoch watchdog")]
    Watchdog(#[from] std::io::Error),
    #[error("one engine cannot execute concurrent invocations")]
    ConcurrentRun,
}

/// The only mutable store data supplied to host functions is the caller's
/// explicit state. Wasmtime resource limits remain owned by this wrapper.
pub struct RuntimeStore<T> {
    host: T,
    limits: StoreLimits,
    wall_ms: u64,
}
impl<T> RuntimeStore<T> {
    pub fn host(&self) -> &T {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut T {
        &mut self.host
    }
}

/// A module that passed the EffectLatch ABI validator before JIT compilation.
/// Its underlying Wasmtime module cannot be substituted by callers.
pub struct ValidatedModule {
    module: Module,
}

pub struct BoundedEngine {
    engine: Engine,
    active: AtomicBool,
}

impl BoundedEngine {
    pub fn new() -> Result<Self, RuntimeError> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .wasm_memory64(false)
            .wasm_multi_memory(false)
            .wasm_relaxed_simd(false)
            .max_wasm_stack(512 * 1024);
        Ok(Self {
            engine: Engine::new(&config)?,
            active: AtomicBool::new(false),
        })
    }

    /// Revalidate before compilation, even when the control plane validated
    /// the same content-addressed bytes at upload.
    pub fn compile(&self, bytes: &[u8]) -> Result<ValidatedModule, RuntimeError> {
        validate::validate(bytes)?;
        Ok(ValidatedModule {
            module: Module::new(&self.engine, bytes)?,
        })
    }

    fn new_store<T>(
        &self,
        host: T,
        requested: Limits,
        operator_caps: Limits,
    ) -> Result<Store<RuntimeStore<T>>, RuntimeError> {
        let limits = requested.validate(operator_caps)?;
        let memory_bytes = usize::try_from(limits.memory_bytes)
            .map_err(|_| effectlatch_domain::ConfigError::InvalidLimit("memory_bytes"))?;
        let data = RuntimeStore {
            host,
            wall_ms: limits.wall_ms,
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_bytes)
                .instances(1)
                .memories(1)
                .tables(0)
                .build(),
        };
        let mut store = Store::new(&self.engine, data);
        store.limiter(|data| &mut data.limits);
        store.set_fuel(limits.fuel)?;
        store.set_epoch_deadline(1);
        Ok(store)
    }

    /// Only the five imports accepted by `compile` can be called by the guest.
    /// The callback configures their host implementation without access to the
    /// engine or store limits. No WASI or ambient linker is installed.
    /// The outer supervisor must still kill blocked host calls at wall time.
    pub fn execute<T: 'static, F>(
        &self,
        module: &ValidatedModule,
        host: T,
        requested: Limits,
        operator_caps: Limits,
        configure_imports: F,
    ) -> Result<i32, RuntimeError>
    where
        F: FnOnce(&mut Linker<RuntimeStore<T>>) -> Result<(), RuntimeError>,
    {
        let lock = self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RuntimeError::ConcurrentRun)?;
        debug_assert!(!lock);
        let _guard = ActiveGuard(&self.active);
        let mut store = self.new_store(host, requested, operator_caps)?;
        let mut linker = Linker::new(&self.engine);
        configure_imports(&mut linker)?;
        let wall_ms = store.data().wall_ms;
        let watchdog = EpochWatchdog::start(&self.engine, Duration::from_millis(wall_ms))?;
        let instance = linker.instantiate(&mut store, &module.module)?;
        let run = instance.get_typed_func::<(), i32>(&mut store, "run")?;
        let result = run.call(&mut store, ())?;
        drop(watchdog);
        Ok(result)
    }
}

struct ActiveGuard<'a>(&'a AtomicBool);
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct EpochWatchdog {
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl EpochWatchdog {
    fn start(engine: &Engine, deadline: Duration) -> Result<Self, std::io::Error> {
        let (stop, receiver) = mpsc::channel();
        let engine = engine.clone();
        let thread = thread::Builder::new()
            .name("effectlatch-epoch-watchdog".into())
            .spawn(move || {
                if receiver.recv_timeout(deadline).is_err() {
                    engine.increment_epoch();
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for EpochWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
