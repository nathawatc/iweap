use iweap::{Installer, InstallerService, OBJECT_PATH, SERVICE_NAME};
use std::error::Error;

fn main() {
    if !iweap::filesystem::running_as_root() {
        eprintln!("iweap-service: must run as root");
        std::process::exit(1);
    }

    if let Err(error) = zbus::block_on(run_service()) {
        eprintln!("iweap-service: {error}");
        std::process::exit(1);
    }
}

async fn run_service() -> Result<(), Box<dyn Error>> {
    let service = InstallerService::new(Installer::system());
    let _connection = zbus::connection::Builder::system()?
        .name(SERVICE_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await?;
    std::future::pending::<()>().await;
    Ok(())
}
