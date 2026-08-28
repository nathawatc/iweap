use futures_lite::future;
use iweap::{Installer, InstallerService, OBJECT_PATH, SERVICE_NAME, ServiceActivity};
use std::error::Error;
use std::time::Duration;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    let activity = service.activity();
    let connection = zbus::connection::Builder::system()?
        .name(SERVICE_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await?;

    wait_for_idle(&connection, &activity).await;
    if !connection.is_closed() {
        connection.close().await?;
    }
    Ok(())
}

async fn wait_for_idle(connection: &zbus::Connection, activity: &ServiceActivity) {
    loop {
        if connection.is_closed() {
            return;
        }
        let activity_event = connection.monitor_activity();
        let timer = async_io::Timer::after(IDLE_TIMEOUT);
        let timed_out = future::or(
            async {
                activity_event.await;
                false
            },
            async {
                timer.await;
                true
            },
        )
        .await;
        if !timed_out {
            continue;
        }
        if activity.stop_if_idle() {
            return;
        }
    }
}
