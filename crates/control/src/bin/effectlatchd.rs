use effectlatch_control::{auth::Principals, config::Config, scheduler, server};
use effectlatch_store::Store;
use std::{
    error::Error,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err("configuration must be a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("configuration file exceeds limit".into());
    }
    Ok(bytes)
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("shutdown signal registration failed");
    }
}
async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--config" {
        return Err("usage: effectlatchd --config PATH".into());
    }
    let config = Config::parse(&read_bounded(Path::new(&args[1]), 65_536)?)?;
    let principals_path =
        std::env::var_os("EFFECTLATCH_PRINCIPALS_FILE").ok_or("principal file is required")?;
    let principals = Arc::new(Principals::load(Path::new(&principals_path))?);
    let url_path =
        std::env::var_os("EFFECTLATCH_DATABASE_URL_FILE").ok_or("database URL file is required")?;
    let url = String::from_utf8(read_bounded(Path::new(&url_path), 4096)?)?;
    let store = Arc::new(Store::connect(url.trim(), 16).await?);
    let migrations = PathBuf::from("migrations");
    let result: Result<_, Box<dyn Error>> = async {
        store.check_schema(&migrations).await?;
        let listener = tokio::net::TcpListener::bind(config.server.bind).await?;
        let (stop_sweeper, stop_receiver) = tokio::sync::watch::channel(false);
        let mut sweeper = tokio::spawn(scheduler::sweep(
            store.clone(),
            effectlatch_store::scheduler::ReapPolicy {
                max_attempts: config.limits.max_attempts as u8,
                max_pending_global: config.limits.max_pending_global,
                max_pending_tenant: config.limits.max_pending_per_tenant,
            },
            config.limits.sweep_ms,
            stop_receiver,
        ));
        let served = server::serve(
            listener,
            server::router(store.clone(), migrations, principals, &config),
            shutdown(),
        )
        .await;
        if stop_sweeper.send(true).is_err() {
            eprintln!("lease sweeper exited before shutdown");
        }
        if tokio::time::timeout(std::time::Duration::from_secs(3), &mut sweeper)
            .await
            .is_err()
        {
            sweeper.abort();
            if let Err(error) = sweeper.await
                && !error.is_cancelled()
            {
                eprintln!("lease sweeper join failed: {error}");
            }
        }
        Ok(served?)
    }
    .await;
    store.close().await;
    let stats = result?;
    eprintln!("control shutdown: {stats:?}");
    Ok(())
}
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run()),
        Err(error) => Err(Box::new(error) as Box<dyn Error>),
    };
    if let Err(error) = result {
        eprintln!("control failed: {error}");
        std::process::exit(2);
    }
}
