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

    server.run().await?;
    Ok(())
}
