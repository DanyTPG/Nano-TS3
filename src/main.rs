use nano_ts3::database::Database;
use nano_ts3::server::Server;
use std::env;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    println!("=======================================================");
    println!("             Nano-TS3 Minimal Server v0.1.0            ");
    println!("=======================================================");

    let port: u16 = env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(9988);

    let db_path = "nano_ts3.db";
    let db = Database::open(db_path)?;

    // Check if initial admin token was generated
    if let Some(token) = db.get_or_create_initial_admin_token()? {
        println!();
        println!("*******************************************************");
        println!("       SERVER ADMIN PRIVILEGE KEY GENERATED            ");
        println!("*******************************************************");
        println!("Token: {}", token);
        println!();
        println!("Redeem in TeamSpeak 3 Client: Permissions -> Use Privilege Key");
        println!("*******************************************************");
        println!();
    }

    let bind_addr = format!("0.0.0.0:{}", port);
    let server = Server::bind(&bind_addr, db).await?;

    info!("Server successfully initialized on port {}", port);
    println!("Ready for TeamSpeak 3 clients on udp://127.0.0.1:{}", port);

    let running = server.run();
    tokio::pin!(running);

    tokio::select! {
        res = &mut running => {
            res?;
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received, disconnecting clients gracefully");
            server.shutdown().await;
            info!("Shutdown complete, bye");
        }
    }
    Ok(())
}

/// Resolves on the first termination signal the OS delivers to this process:
/// Ctrl+C, Ctrl+Break, a closing console window, or SIGTERM/SIGINT on unix.
async fn shutdown_signal() {
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_c};

        let mut sig_c = ctrl_c().expect("install ctrl_c handler");
        let mut sig_break = ctrl_break().expect("install ctrl_break handler");
        let mut sig_close = ctrl_close().expect("install ctrl_close handler");

        tokio::select! {
            _ = sig_c.recv() => info!("Ctrl+C received"),
            _ = sig_break.recv() => info!("Ctrl+Break received"),
            _ = sig_close.recv() => info!("Console close received"),
        }
    }
    #[cfg(not(windows))]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sig_term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sig_int = signal(SignalKind::interrupt()).expect("install SIGINT handler");

        tokio::select! {
            _ = sig_term.recv() => info!("SIGTERM received"),
            _ = sig_int.recv() => info!("SIGINT received"),
        }
    }
}
