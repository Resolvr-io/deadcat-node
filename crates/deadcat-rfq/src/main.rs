mod daemon;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    daemon::init_tracing()?;
    daemon::run_cli().await
}
