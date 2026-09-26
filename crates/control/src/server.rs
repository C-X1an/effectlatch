//! Bounded HTTP/1 control listener. Guest execution is not hosted here.
use crate::{api, auth::Principals, config};
use axum::{Extension, Router, extract::State, http::StatusCode, routing::get};
use effectlatch_store::Store;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};

#[derive(Clone)]
struct Health {
    store: Arc<Store>,
    migrations: PathBuf,
}
pub fn router(
    store: Arc<Store>,
    migrations: PathBuf,
    principals: Arc<Principals>,
    config: &config::Config,
) -> Router {
    let api = api::routes(
        api::ApiState::new(store.clone(), config),
        principals,
        config.server.max_json_bytes as usize,
        config.server.max_module_bytes as usize,
    );
    Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .with_state(Health { store, migrations })
        .merge(api)
}
async fn ready(State(state): State<Health>, Extension(peer): Extension<SocketAddr>) -> StatusCode {
    if !peer.ip().is_loopback() {
        return StatusCode::FORBIDDEN;
    }
    match state.store.check_schema(&state.migrations).await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Default, Debug)]
pub struct ConnectionStats {
    pub completed: u64,
    pub protocol_errors: u64,
    pub deadline_exceeded: u64,
    pub task_failures: u64,
    pub aborted_on_shutdown: u64,
}
fn record(stats: &mut ConnectionStats, result: Result<u8, tokio::task::JoinError>) {
    match result {
        Ok(0) => stats.completed += 1,
        Ok(1) => stats.protocol_errors += 1,
        Ok(_) => stats.deadline_exceeded += 1,
        Err(_) => stats.task_failures += 1,
    }
}
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> Result<ConnectionStats, std::io::Error> {
    tokio::pin!(shutdown);
    let mut tasks = JoinSet::new();
    let mut stats = ConnectionStats::default();
    let accept_error = loop {
        tokio::select! {
            _ = &mut shutdown => break None,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result { record(&mut stats, result); }
            }
            accepted = listener.accept(), if tasks.len() < 128 => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => break Some(error),
                };
                let service = TowerToHyperService::new(router.clone().layer(Extension(peer)));
                tasks.spawn(async move {
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(2))
                        .max_headers(64).max_buf_size(32_768).keep_alive(false);
                    match tokio::time::timeout(Duration::from_secs(15), builder.serve_connection(TokioIo::new(stream), service)).await {
                        Ok(Ok(())) => 0,
                        Ok(Err(_)) => 1,
                        Err(_) => 2,
                    }
                });
            }
        }
    };
    drop(listener);
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            record(&mut stats, result);
        }
    };
    if tokio::time::timeout(Duration::from_secs(3), drain)
        .await
        .is_err()
    {
        stats.aborted_on_shutdown = tasks.len() as u64;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    match accept_error {
        Some(error) => Err(error),
        None => Ok(stats),
    }
}
